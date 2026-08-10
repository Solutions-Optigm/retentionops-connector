// Command retentionops-connector runs retention work inside a customer's network, on behalf of
// a RetentionOps control plane that never sees their data or their credentials.
//
// It has five subcommands and no daemon-management surface of its own: process supervision
// belongs to systemd, Kubernetes or the container runtime, all of which do it better than an
// agent that reinvents it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/agent"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/controlplane"
	"github.com/solutions-optigm/retentionops-connector/internal/doctor"
	"github.com/solutions-optigm/retentionops-connector/internal/enrollment"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	"github.com/solutions-optigm/retentionops-connector/internal/telemetry"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "0.1.0-dev"

const defaultConfigPath = "/etc/retentionops/connector.yaml"

const usage = `retentionops-connector %s — RetentionOps data-plane connector

Usage:
  retentionops-connector run              [--config PATH]
  retentionops-connector enroll           [--config PATH] [--if-needed] --url URL --organization UUID --token TOKEN
  retentionops-connector validate-config  [--config PATH]
  retentionops-connector doctor           [--config PATH]
  retentionops-connector source test      [--config PATH] DATA_SOURCE_ID
  retentionops-connector source discover  [--config PATH] DATA_SOURCE_ID
  retentionops-connector version

The connector only ever dials out, over HTTPS, to the control plane named in its configuration.
It opens no inbound port for RetentionOps, and it resolves database credentials locally through
the secret providers this build supports: %s.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		fmt.Printf(usage, version, joinNames())
		return errors.New("a subcommand is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch arguments[0] {
	case "run":
		return runConnector(ctx, arguments[1:])
	case "enroll":
		return runEnroll(ctx, arguments[1:])
	case "validate-config":
		return runValidate(arguments[1:])
	case "doctor":
		return runDoctor(ctx, arguments[1:])
	case "source":
		return runSource(ctx, arguments[1:])
	case "version":
		fmt.Printf("retentionops-connector %s (%s, protocol v%s)\n", version, runtime.Version(), protocolv1.Version)
		return nil
	case "-h", "--help", "help":
		fmt.Printf(usage, version, joinNames())
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q", arguments[0])
	}
}

func joinNames() string {
	names := secrets.Default().Names()
	joined := ""
	for index, name := range names {
		if index > 0 {
			joined += ", "
		}
		joined += name
	}
	return joined
}

func configFlag(set *flag.FlagSet) *string {
	return set.String("config", defaultConfigPath, "path to the connector configuration file")
}

func runConnector(ctx context.Context, arguments []string) error {
	set := flag.NewFlagSet("run", flag.ContinueOnError)
	path := configFlag(set)
	if err := set.Parse(arguments); err != nil {
		return err
	}
	configuration, err := config.Load(*path)
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(configuration.Telemetry.LogFormat, configuration.Telemetry.LogLevel)

	if err := config.RequireDirectoryIsPrivate(configuration.Identity.Directory); err != nil {
		return err
	}
	id, err := identity.Load(configuration.Identity.Directory)
	if err != nil {
		return err
	}
	client, err := controlplane.New(
		configuration.ControlPlane.URL,
		configuration.ControlPlane.CAFile,
		version,
		id,
		// The client timeout must outlast a long poll, or every idle cycle would look like a
		// network failure and the backoff would never settle.
		time.Duration(configuration.ControlPlane.PollWaitSeconds+30)*time.Second,
	)
	if err != nil {
		return err
	}

	metrics := telemetry.NewMetrics()
	server := telemetry.Listen(configuration.Telemetry.MetricsAddress, metrics, log)
	if server != nil {
		defer func() {
			shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
	}

	connector, err := agent.New(configuration, id, client, secrets.Default(), metrics, log, version)
	if err != nil {
		return err
	}
	if err := connector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	log.Info("connector stopped")
	return nil
}

func runEnroll(ctx context.Context, arguments []string) error {
	set := flag.NewFlagSet("enroll", flag.ContinueOnError)
	path := configFlag(set)
	url := set.String("url", "", "control-plane base URL, for example https://connector.retentionops.ca")
	organization := set.String("organization", "", "organization UUID shown in the console")
	token := set.String("token", "", "single-use enrollment token shown in the console")
	ifNeeded := set.Bool("if-needed", false, "reuse a valid local identity without contacting the control plane")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *url == "" || *organization == "" || *token == "" {
		return errors.New("--url, --organization and --token are all required")
	}
	configuration, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *ifNeeded {
		existing, loadErr := identity.Load(configuration.Identity.Directory)
		if loadErr == nil {
			if existing.OrganizationID != *organization {
				return fmt.Errorf("existing identity belongs to organization %s, not %s",
					existing.OrganizationID, *organization)
			}
			fmt.Printf("Already enrolled as connector %s; no network request was made.\n", existing.ConnectorID)
			return nil
		}
	}
	id, err := enrollment.Run(ctx, enrollment.Request{
		ControlPlaneURL: *url,
		OrganizationID:  *organization,
		Token:           *token,
		Version:         version,
		CAFile:          configuration.ControlPlane.CAFile,
		Directory:       configuration.Identity.Directory,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Enrolled.\n")
	fmt.Printf("  connector id            %s\n", id.ConnectorID)
	fmt.Printf("  organization            %s\n", id.OrganizationID)
	fmt.Printf("  identity file           %s/%s\n", configuration.Identity.Directory, identity.FileName)
	fmt.Printf("  pinned control-plane key %s\n", identity.Fingerprint(id.ControlPlaneKey()))
	fmt.Printf("\nCompare that fingerprint with the one shown in the console before you start the connector.\n")
	return nil
}

func runValidate(arguments []string) error {
	set := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	path := configFlag(set)
	if err := set.Parse(arguments); err != nil {
		return err
	}
	configuration, err := config.Load(*path)
	if err != nil {
		return err
	}
	registry := secrets.Default()
	for id, source := range configuration.Sources {
		for role, credential := range map[string]config.Credential{"reader": source.Reader, "executor": source.Executor} {
			if role == "executor" && !source.Safety.GrantsDelete() {
				continue
			}
			if !registry.Supports(credential.Password.Provider) {
				return fmt.Errorf("source %s: %s uses provider %q, which this build does not support",
					id, role, credential.Password.Provider)
			}
		}
	}
	digest, err := configuration.PolicyDigest()
	if err != nil {
		return err
	}
	fmt.Printf("Configuration is valid.\n")
	fmt.Printf("  sources        %d\n", len(configuration.Sources))
	fmt.Printf("  policy digest  %s\n", digest)
	return nil
}

func runDoctor(ctx context.Context, arguments []string) error {
	set := flag.NewFlagSet("doctor", flag.ContinueOnError)
	path := configFlag(set)
	if err := set.Parse(arguments); err != nil {
		return err
	}
	configuration, err := config.Load(*path)
	if err != nil {
		return err
	}
	// A missing identity is a finding, not a crash: "you have not enrolled yet" is precisely the
	// kind of thing an operator runs the doctor to be told.
	id, _ := identity.Load(configuration.Identity.Directory)
	report := doctor.Run(ctx, configuration, id, secrets.Default())
	report.Write(os.Stdout)
	if !report.Healthy() {
		return errors.New("at least one check failed")
	}
	return nil
}

func runSource(ctx context.Context, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("source requires an action: test or discover")
	}
	action := arguments[0]
	set := flag.NewFlagSet("source "+action, flag.ContinueOnError)
	path := configFlag(set)
	if err := set.Parse(arguments[1:]); err != nil {
		return err
	}
	if set.NArg() != 1 {
		return errors.New("exactly one data source id is required")
	}
	sourceID := set.Arg(0)

	configuration, err := config.Load(*path)
	if err != nil {
		return err
	}
	source, known := configuration.Source(sourceID)
	if !known {
		return fmt.Errorf("source %s is not in %s", sourceID, *path)
	}
	log := telemetry.NewLogger(configuration.Telemetry.LogFormat, configuration.Telemetry.LogLevel)
	adapter := postgres.New(sourceID, source, secrets.Default(), log)

	switch action {
	case "test":
		statistics, err := adapter.TestConnection(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", source.Describe())
		fmt.Printf("  server            %s\n", statistics.DatabaseVersion)
		fmt.Printf("  tls               %s\n", statistics.TLSMode)
		fmt.Printf("  reader            %s\n", validated(statistics.ReaderValidated))
		fmt.Printf("  executor          %s\n", validated(statistics.ExecutorValidated))
		fmt.Printf("  allow-listed      %d table(s)\n", source.Safety.AllowedTableCount())
		return nil
	case "discover":
		statistics, err := adapter.Discover(ctx)
		if err != nil {
			return err
		}
		for _, table := range statistics.Tables {
			fmt.Printf("%s.%s (%d columns)\n", table.Schema, table.Table, len(table.Columns))
		}
		return nil
	default:
		return fmt.Errorf("unknown source action %q", action)
	}
}

func validated(ok bool) string {
	if ok {
		return "validated"
	}
	return "not validated"
}
