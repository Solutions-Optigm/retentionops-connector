// Package execution implements the local, two-step opt-in to destructive execution.
package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
	"gopkg.in/yaml.v3"
)

const marker = ".retentionops-execution-enable-v1"

type Table struct {
	Schema          string
	Name            string
	RetentionColumn string
}

type PrepareOptions struct {
	ConfigPath        string
	SourceID          string
	ExecutorRole      string
	ExecutorSecretRef string
	Tables            []Table
	MaxDeleteRows     int
	MaxBatchSize      int
	OutputDirectory   string
}

type manifest struct {
	Version          int    `json:"version"`
	SourceID         string `json:"source_id"`
	ConfigPath       string `json:"config_path"`
	BaseConfigDigest string `json:"base_config_digest"`
	PendingDigest    string `json:"pending_config_digest"`
}

func Prepare(options PrepareOptions) error {
	if len(options.Tables) == 0 {
		return errors.New("execution enable: at least one --table is required")
	}
	if options.MaxDeleteRows <= 0 || options.MaxBatchSize <= 0 {
		return errors.New("execution enable: row and batch ceilings must be positive")
	}
	configuration, err := config.Load(options.ConfigPath)
	if err != nil {
		return err
	}
	source, ok := configuration.Source(options.SourceID)
	if !ok {
		return fmt.Errorf("execution enable: source %s is absent", options.SourceID)
	}
	if source.Mode != config.SourceModeDiscoveryOnly || source.Safety.GrantsDelete() {
		return errors.New("execution enable: source is not discovery-only")
	}
	source.Mode = config.SourceModeExecution
	source.Executor = config.Credential{Username: options.ExecutorRole, Password: config.SecretRef{Provider: "file", Ref: options.ExecutorSecretRef}}
	tables := make([][2]string, 0, len(options.Tables))
	for _, table := range options.Tables {
		source.Safety.Tables = append(source.Safety.Tables, policy.TableRule{
			Schema: table.Schema, Table: table.Name, Actions: []policy.Action{policy.ActionInspect, policy.ActionDelete},
			RetentionColumns: []string{table.RetentionColumn}, MaxDeleteRows: options.MaxDeleteRows,
			MaxBatchSize: options.MaxBatchSize,
		})
		tables = append(tables, [2]string{table.Schema, table.Name})
	}
	if err := configuration.Validate(); err != nil {
		return fmt.Errorf("execution enable: pending configuration is invalid: %w", err)
	}
	output, err := filepath.Abs(options.OutputDirectory)
	if err != nil {
		return err
	}
	if err := prepareDirectory(output); err != nil {
		return err
	}
	pending, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	base, err := os.ReadFile(options.ConfigPath) //nolint:gosec // explicit local policy
	if err != nil {
		return err
	}
	document := manifest{Version: 1, SourceID: options.SourceID, ConfigPath: options.ConfigPath,
		BaseConfigDigest: digest(base), PendingDigest: digest(pending)}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	artifacts := map[string][]byte{
		"connector.yaml": pending,
		"roles.sql":      []byte(postgres.RenderExecutorSQL(source.Database, source.Executor, tables)),
		"execution.json": append(encoded, '\n'),
		marker:           []byte("RetentionOps local execution enablement v1\n"),
	}
	for name, content := range artifacts {
		if err := write(filepath.Join(output, name), content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

type ApplyOptions struct {
	ConfigPath         string
	Bundle             string
	ExecutorSecretFile string
	ExecutorSecret     []byte
	Repair             bool
}

func Apply(options ApplyOptions) error {
	bundle, err := filepath.Abs(options.Bundle)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(bundle, marker)); err != nil {
		return errors.New("execution apply: directory is not an execution-enablement bundle")
	}
	rawManifest, err := os.ReadFile(filepath.Join(bundle, "execution.json")) //nolint:gosec // local reviewed bundle
	if err != nil {
		return err
	}
	var document manifest
	if err := json.Unmarshal(rawManifest, &document); err != nil || document.Version != 1 {
		return errors.New("execution apply: execution.json is invalid")
	}
	current, err := os.ReadFile(options.ConfigPath) //nolint:gosec // explicit local policy
	if err != nil {
		return err
	}
	if digest(current) != document.BaseConfigDigest {
		return errors.New("execution apply: local policy changed after preparation; generate and review a new bundle")
	}
	pending, err := os.ReadFile(filepath.Join(bundle, "connector.yaml")) //nolint:gosec // local reviewed bundle
	if err != nil {
		return err
	}
	if digest(pending) != document.PendingDigest {
		return errors.New("execution apply: pending connector.yaml digest mismatch")
	}
	configuration, err := config.Load(filepath.Join(bundle, "connector.yaml"))
	if err != nil {
		return err
	}
	source, ok := configuration.Source(document.SourceID)
	if !ok || source.Mode != config.SourceModeExecution {
		return errors.New("execution apply: pending source is not execution-enabled")
	}
	secret := bytes.TrimRight(options.ExecutorSecret, "\r\n")
	if len(secret) == 0 {
		if options.ExecutorSecretFile == "" {
			return errors.New("execution apply: executor secret is empty")
		}
		secret, err = readPrivate(options.ExecutorSecretFile)
		if err != nil {
			return err
		}
	}
	if len(secret) == 0 {
		return errors.New("execution apply: executor secret is empty")
	}
	if len(secret) > 64*1024 {
		return errors.New("execution apply: executor secret is unexpectedly large")
	}
	secretTarget := source.Executor.Password.Ref
	if filepath.Clean(options.ConfigPath) != "/etc/retentionops/connector.yaml" {
		secretTarget = filepath.Join(filepath.Dir(options.ConfigPath), "runtime", "secrets", filepath.Base(secretTarget))
	}
	if err := atomicWrite(secretTarget, secret, 0o400); err != nil {
		return err
	}
	backup := options.ConfigPath + ".backup-" + time.Now().UTC().Format("20060102T150405Z")
	if err := write(backup, current, 0o640); err != nil {
		return err
	}
	if err := atomicWrite(options.ConfigPath, pending, 0o640); err != nil {
		return err
	}
	return protectRuntimeFiles(options.ConfigPath, secretTarget)
}

func protectRuntimeFiles(configPath, secretPath string) error {
	if os.Geteuid() != 0 || filepath.Clean(configPath) != "/etc/retentionops/connector.yaml" {
		return nil
	}
	account, err := user.Lookup("retentionops")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(configPath, 0, gid); err != nil {
		return err
	}
	if err := os.Chown(secretPath, uid, gid); err != nil {
		return err
	}
	return nil
}

func ParseTable(value string) (Table, error) {
	target, column, found := strings.Cut(value, ":")
	if !found {
		return Table{}, errors.New("table must use schema.table:retention_column")
	}
	schema, table, found := strings.Cut(target, ".")
	if !found || schema == "" || table == "" || column == "" {
		return Table{}, errors.New("table must use schema.table:retention_column")
	}
	return Table{Schema: schema, Name: table, RetentionColumn: column}, nil
}

func prepareDirectory(path string) error {
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("execution enable: output directory must be private")
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			return errors.New("execution enable: output directory must be empty")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(path, 0o700)
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&fs.FileMode(0o077) != 0 {
		return nil, errors.New("execution apply: executor secret file is not private")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // explicit private secret input
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimRight(raw, "\r\n")
	if len(raw) == 0 {
		return nil, errors.New("execution apply: executor secret is empty")
	}
	return raw, nil
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func write(path string, content []byte, mode fs.FileMode) error {
	if err := os.WriteFile(path, content, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func atomicWrite(path string, content []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".retentionops-execution-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
