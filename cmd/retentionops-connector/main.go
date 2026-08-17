// Command retentionops-connector runs retention work inside a customer's network, on behalf of
// a RetentionOps control plane that never sees their data or their credentials.
//
// It has no daemon-management surface of its own: process supervision belongs to systemd or the
// container runtime, both of which do it better than an agent that reinvents it.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/agent"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/controlplane"
	"github.com/solutions-optigm/retentionops-connector/internal/doctor"
	"github.com/solutions-optigm/retentionops-connector/internal/enrollment"
	"github.com/solutions-optigm/retentionops-connector/internal/execution"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	"github.com/solutions-optigm/retentionops-connector/internal/initializer"
	"github.com/solutions-optigm/retentionops-connector/internal/installer"
	"github.com/solutions-optigm/retentionops-connector/internal/localsecret"
	"github.com/solutions-optigm/retentionops-connector/internal/scope"
	"github.com/solutions-optigm/retentionops-connector/internal/telemetry"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
	"github.com/solutions-optigm/retentionops-connector/secrets"
	"golang.org/x/term"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "0.1.0-dev"

const defaultConfigPath = "/etc/retentionops/connector.yaml"

const usage = `retentionops-connector %s — RetentionOps data-plane connector

Usage:
  retentionops-connector init --platform systemd|compose --source UUID --organization UUID --control-plane HTTPS_URL [--install [--repair]]
  retentionops-connector init --answers-file PATH
  retentionops-connector install --bundle PATH [--repair] [--reader-secret-file PATH] [--token-file PATH]
  retentionops-connector execution enable --config PATH --source UUID --table schema.table:column
  retentionops-connector execution apply  --config PATH --bundle PATH --database-role-applied
  retentionops-connector run              [--config PATH]
  retentionops-connector enroll           [--config PATH] [--if-needed] --url URL --organization UUID --token-file PATH
  retentionops-connector validate-config  [--config PATH]
  retentionops-connector doctor           [--config PATH]
  retentionops-connector source test      [--config PATH] DATA_SOURCE_ID
  retentionops-connector source discover  [--config PATH] DATA_SOURCE_ID
  retentionops-connector source roles     [--config PATH] DATA_SOURCE_ID
  retentionops-connector source scope     [--config PATH] DATA_SOURCE_ID
  retentionops-connector secret set       [--config PATH] [--source UUID] [--role reader|executor] [--from-file PATH]
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
	case "init":
		return runInit(ctx, arguments[1:], os.Stdin, os.Stdout)
	case "install":
		return runInstall(ctx, arguments[1:], os.Stdin, os.Stdout)
	case "execution":
		return runExecution(arguments[1:], os.Stdin, os.Stdout)
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
	case "secret":
		return runSecret(arguments[1:], os.Stdin, os.Stdout)
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

func runInit(ctx context.Context, arguments []string, in *os.File, out *os.File) error {
	directory, repair, err := runInitIO(arguments, in, out)
	if err != nil || directory == "" {
		return err
	}
	// Piped input cannot reach the token prompt: the question loop above reads through a buffer
	// that has already consumed whatever followed the last answer. Interactively that never
	// happens — a terminal hands over one line at a time — so this refuses the one shape where
	// the token would be silently swallowed, and names the form that does work unattended.
	if !term.IsTerminal(int(in.Fd())) {
		return errors.New(
			"init --install needs a terminal for the enrollment token; " +
				"for an unattended installation run init, then install --bundle --token-file")
	}
	// Applying what was just written, in the same run, from the directory `init` actually chose.
	// The alternative the console used to print was a second command carrying "$PWD/..." — which
	// is wrong the moment an operator answers the output-directory question with anything else.
	fmt.Fprintln(out, "\nApplying this bundle. Review it instead by running init without --install.")
	return installer.Run(ctx, installer.Options{
		Bundle: directory, Root: "/", Repair: repair, Version: version,
		Prompts: terminalPrompts(in, out), Out: out,
	})
}

// runInitIO returns the bundle directory when the caller asked for it to be applied immediately,
// along with whether an earlier attempt's files may be replaced.
func runInitIO(arguments []string, in io.Reader, out io.Writer) (string, bool, error) {
	set := flag.NewFlagSet("init", flag.ContinueOnError)
	set.SetOutput(out)
	platform := set.String("platform", "", "deployment platform: systemd or compose")
	sourceID := set.String("source", "", "data source UUID from the console")
	organizationID := set.String("organization", "", "organization UUID from the console")
	controlPlane := set.String("control-plane", "", "RetentionsOps HTTPS control-plane URL")
	answersFile := set.String("answers-file", "", "strict versioned YAML answers file")
	apply := set.Bool("install", false, "apply the generated bundle immediately, in this same run")
	// Needed more often than it looks: an installation that failed at enrolment has already
	// written the runtime configuration, so the corrected bundle differs from what is on disk and
	// the installer refuses it. Without this the operator has to abandon --install entirely.
	repair := set.Bool("repair", false, "with --install, back up and replace conflicting generated runtime files")
	if err := set.Parse(arguments); err != nil {
		return "", false, err
	}
	if set.NArg() != 0 {
		return "", false, errors.New("init accepts flags only")
	}
	var answers initializer.Answers
	if *answersFile != "" {
		if *platform != "" || *sourceID != "" || *organizationID != "" || *controlPlane != "" {
			return "", false, errors.New("--answers-file cannot be combined with interactive installation flags")
		}
		loaded, err := initializer.LoadAnswers(*answersFile)
		if err != nil {
			return "", false, err
		}
		answers = loaded
	} else {
		if *platform == "" || *sourceID == "" || *controlPlane == "" {
			return "", false, errors.New("--platform, --source and --control-plane are required in interactive mode")
		}
		if err := initializer.ValidateControlPlaneFlag(*controlPlane); err != nil {
			return "", false, err
		}
		answers = initializer.Answers{
			Version: initializer.AnswersVersion, Platform: *platform, SourceID: *sourceID,
			OrganizationID: *organizationID, ControlPlane: initializer.ControlPlane{URL: *controlPlane},
		}
		var err error
		answers, err = initializer.Interactive(in, out, answers)
		if err != nil {
			return "", false, err
		}
	}
	if err := initializer.Generate(answers); err != nil {
		return "", false, err
	}
	fmt.Fprintf(out, "Installation bundle written to %s. No SQL was executed and no network request was made.\n", answers.OutputDirectory)
	if !*apply {
		return "", false, nil
	}
	return answers.OutputDirectory, *repair, nil
}

func runInstall(ctx context.Context, arguments []string, in *os.File, out *os.File) error {
	set := flag.NewFlagSet("install", flag.ContinueOnError)
	set.SetOutput(out)
	bundle := set.String("bundle", "", "private installation bundle written by init")
	repair := set.Bool("repair", false, "back up and replace conflicting generated runtime files")
	readerSecretFile := set.String("reader-secret-file", "", "private file containing the PostgreSQL reader password")
	tokenFile := set.String("token-file", "", "private file containing the single-use enrollment token")
	organization := set.String("organization", "", "organization UUID for a legacy bundle")
	caFile := set.String("ca-file", "", "PostgreSQL CA source path for a legacy bundle")
	nonInteractive := set.Bool("non-interactive", false, "require every sensitive input through a private file")
	databaseRoleApplied := set.Bool("database-role-applied", false, "confirm reviewed roles.sql was already applied")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *bundle == "" || set.NArg() != 0 {
		return errors.New("install requires --bundle and accepts flags only")
	}
	inputs := installer.Inputs{Organization: *organization, CASourceFile: *caFile}
	if *readerSecretFile != "" {
		secret, err := readPrivateValue(*readerSecretFile, "reader secret")
		if err != nil {
			return err
		}
		inputs.ReaderSecret = secret
	}
	if *tokenFile != "" {
		token, err := readPrivateToken(*tokenFile)
		if err != nil {
			return err
		}
		inputs.Token = token
	}
	return installer.Run(ctx, installer.Options{
		Bundle: *bundle, Root: "/", Repair: *repair, NonInteractive: *nonInteractive,
		Version: version, Inputs: inputs, Prompts: terminalPrompts(in, out), Out: out,
		DatabaseRoleApplied: *databaseRoleApplied,
	})
}

// terminalPrompts is the only place a secret is read from a person.
//
// Masked, and never from an argument: an argument is in the process list, in the shell history,
// and in whatever the operator pastes into a support ticket (ADR-032).
func terminalPrompts(in *os.File, out io.Writer) installer.Prompts {
	return installer.Prompts{
		Secret: func(label string) ([]byte, error) { return readMasked(in, out, label+": ") },
		Token: func() (string, error) {
			raw, err := readMasked(in, out, "Single-use enrollment token: ")
			return strings.TrimSpace(string(raw)), err
		},
		Confirm: func(question string) (bool, error) {
			fmt.Fprintf(out, "%s [y/N]: ", question)
			answer, err := bufio.NewReader(in).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return false, err
			}
			answer = strings.ToLower(strings.TrimSpace(answer))
			return answer == "y" || answer == "yes", nil
		},
	}
}

func readMasked(in *os.File, out io.Writer, prompt string) ([]byte, error) {
	fmt.Fprint(out, prompt)
	if term.IsTerminal(int(in.Fd())) {
		value, err := term.ReadPassword(int(in.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	value, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return []byte(strings.TrimRight(value, "\r\n")), nil
}

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runExecution(arguments []string, in *os.File, out io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("execution requires an action: enable or apply")
	}
	switch arguments[0] {
	case "enable":
		set := flag.NewFlagSet("execution enable", flag.ContinueOnError)
		set.SetOutput(out)
		path := configFlag(set)
		sourceID := set.String("source", "", "data source UUID")
		executorRole := set.String("executor-role", "retentionops_executor", "PostgreSQL executor role")
		executorRef := set.String("executor-secret-ref", "/etc/retentionops/secrets/executor-password", "runtime secret reference")
		output := set.String("output", "./retentionops-execution-enable", "private review bundle")
		maxRows := set.Int("max-delete-rows", 10_000, "local maximum rows per approved execution")
		maxBatch := set.Int("max-batch-size", 250, "local maximum batch size")
		var rawTables repeatedFlag
		set.Var(&rawTables, "table", "repeatable schema.table:retention_column allow-list entry")
		if err := set.Parse(arguments[1:]); err != nil {
			return err
		}
		if set.NArg() != 0 || *sourceID == "" {
			return errors.New("execution enable requires --source and accepts flags only")
		}
		tables := make([]execution.Table, 0, len(rawTables))
		for _, raw := range rawTables {
			table, err := execution.ParseTable(raw)
			if err != nil {
				return fmt.Errorf("execution enable: --table %q: %w", raw, err)
			}
			tables = append(tables, table)
		}
		if err := execution.Prepare(execution.PrepareOptions{
			ConfigPath: *path, SourceID: *sourceID, ExecutorRole: *executorRole,
			ExecutorSecretRef: *executorRef, Tables: tables, MaxDeleteRows: *maxRows,
			MaxBatchSize: *maxBatch, OutputDirectory: *output,
		}); err != nil {
			return err
		}
		fmt.Fprintf(out, "Execution-enablement review bundle written to %s. No SQL was executed and the live policy was not changed.\n", *output)
		return nil
	case "apply":
		set := flag.NewFlagSet("execution apply", flag.ContinueOnError)
		set.SetOutput(out)
		path := configFlag(set)
		bundle := set.String("bundle", "", "reviewed execution-enablement bundle")
		secretFile := set.String("executor-secret-file", "", "private file containing the executor password")
		databaseRoleApplied := set.Bool("database-role-applied", false, "confirm reviewed roles.sql was applied by the DBA")
		if err := set.Parse(arguments[1:]); err != nil {
			return err
		}
		if set.NArg() != 0 || *bundle == "" {
			return errors.New("execution apply requires --bundle and accepts flags only")
		}
		if !*databaseRoleApplied {
			return errors.New("execution apply requires --database-role-applied after the DBA successfully applies the reviewed roles.sql")
		}
		options := execution.ApplyOptions{ConfigPath: *path, Bundle: *bundle, ExecutorSecretFile: *secretFile}
		if *secretFile == "" {
			secret, err := readMasked(in, out, "PostgreSQL executor password: ")
			if err != nil {
				return err
			}
			options.ExecutorSecret = secret
		}
		if err := execution.Apply(options); err != nil {
			return err
		}
		fmt.Fprintln(out, "Execution enabled in the local policy. Run doctor, then restart the supervised connector only after the executor identity passes.")
		return nil
	default:
		return fmt.Errorf("unknown execution action %q", arguments[0])
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

	connector, err := agent.New(configuration, id, client, secrets.Default(), metrics, log, version, *path)
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
	url := set.String("url", "", "control-plane base URL, for example https://connector.retentionops.app")
	organization := set.String("organization", "", "organization UUID shown in the console")
	tokenFile := set.String("token-file", "", "private file containing the single-use enrollment token")
	ifNeeded := set.Bool("if-needed", false, "reuse a valid local identity without contacting the control plane")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *url == "" || *organization == "" || *tokenFile == "" {
		return errors.New("--url, --organization and --token-file are all required")
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
	token, err := readPrivateToken(*tokenFile)
	if err != nil {
		return err
	}
	id, err := enrollment.Run(ctx, enrollment.Request{
		ControlPlaneURL: *url,
		OrganizationID:  *organization,
		Token:           token,
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

func readPrivateToken(path string) (string, error) {
	raw, err := readPrivateValue(path, "enrollment token")
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("enrollment token file is empty")
	}
	return token, nil
}

func readPrivateValue(path, label string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", label, err)
	}
	if mode := info.Mode().Perm(); mode&fs.FileMode(0o077) != 0 {
		return nil, fmt.Errorf("%s file is mode %#o; it must not be accessible by group or other", label, mode)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // explicit operator-supplied private file
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", label, err)
	}
	if len(raw) > 64*1024 {
		return nil, fmt.Errorf("%s file is unexpectedly large", label)
	}
	return raw, nil
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
		return errors.New("source requires an action: test, discover, roles or scope")
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
	if source.Pending() {
		return fmt.Errorf(
			"source %s has no configuration yet: send it from the RetentionOps console, then run this again",
			sourceID)
	}
	log := telemetry.NewLogger(configuration.Telemetry.LogFormat, configuration.Telemetry.LogLevel)
	adapter := postgres.New(sourceID, source, secrets.Default(), log)

	switch action {
	case "scope":
		return chooseScope(ctx, adapter, configuration, *path, sourceID, os.Stdin, os.Stdout)
	case "roles":
		// Rendered from the effective configuration rather than written at `init`: the database
		// name and the role names arrive from the console, so this is the first moment the script
		// can name what the DBA is actually being asked to create.
		fmt.Print(postgres.RenderRolesSQL(
			source.Database, source.Reader, source.Executor, source.Safety.AllowedSchemas))
		return nil
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

// runSecret writes a database password into the file this host's own configuration names.
//
// The last step of an installation that RetentionOps structurally cannot perform: where to
// connect arrives from the console, the password never does. The value is read from a masked
// prompt or a private file and never from an argument — an argument is in the process list, in
// the shell history and in whatever the operator pastes into a support ticket.
func runSecret(arguments []string, in *os.File, out io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "set" {
		return errors.New("secret requires the action: set")
	}
	set := flag.NewFlagSet("secret set", flag.ContinueOnError)
	set.SetOutput(out)
	path := configFlag(set)
	sourceID := set.String("source", "", "data source UUID; optional when the connector declares one source")
	role := set.String("role", string(localsecret.Reader), "identity whose password is being written: reader or executor")
	fromFile := set.String("from-file", "", "private file holding the password, for unattended installation")
	if err := set.Parse(arguments[1:]); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("secret set accepts flags only; the password is never an argument")
	}
	if *role != string(localsecret.Reader) && *role != string(localsecret.Executor) {
		return fmt.Errorf("unknown role %q: expected reader or executor", *role)
	}

	configuration, err := config.Load(*path)
	if err != nil {
		return err
	}
	identifier := *sourceID
	if identifier == "" {
		if identifier, err = localsecret.OnlySource(configuration); err != nil {
			return err
		}
	}

	value, err := secretReader(*fromFile, in, out, *role)
	if err != nil {
		return err
	}
	if closer, ok := value.(io.Closer); ok {
		defer closer.Close()
	}

	written, err := localsecret.Set(configuration, identifier, localsecret.Role(*role), value)
	if err != nil {
		return err
	}
	// The path, never the value, and no confirmation that it "works": whether PostgreSQL accepts
	// this password is answered by the console's connection test, from a signed result.
	fmt.Fprintf(out, "The %s password for source %s is stored at %s.\n", *role, identifier, written)
	fmt.Fprintln(out, "Nothing was sent anywhere. Run the connection test from the console to check it.")
	return nil
}

func secretReader(fromFile string, in *os.File, out io.Writer, role string) (io.Reader, error) {
	if fromFile == "" {
		masked, err := readMasked(in, out, "PostgreSQL "+role+" password: ")
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(masked), nil
	}
	// Reuses the same privacy check as the enrollment token: a credential handed over in a file
	// that group or other can read has already been disclosed.
	raw, err := readPrivateValue(fromFile, role+" password")
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}

// chooseScope asks PostgreSQL what this reader may enter, then asks the operator what it should.
//
// The list never leaves the host. A customer's schema names are an inventory of what they hold,
// and the whole execution model exists so that RetentionOps does not have one: the control plane
// learns that a boundary was set, never what is inside it. That is also why the choice is made
// here rather than in the console — the console could not offer it without first being told.
func chooseScope(
	ctx context.Context,
	adapter *postgres.Adapter,
	configuration *config.Config,
	path, sourceID string,
	in *os.File,
	out io.Writer,
) error {
	reachable, err := adapter.ReachableSchemas(ctx)
	if err != nil {
		return err
	}
	if len(reachable) == 0 {
		return errors.New("no schema is reachable by the reader identity; grant it USAGE first, then run this again")
	}
	source, _ := configuration.Source(sourceID)
	current := source.Safety.AllowedSchemas

	fmt.Fprintf(out, "\nSchemas this connector's reader identity can enter:\n\n")
	for index, name := range reachable {
		marker := " "
		if slices.Contains(current, name) {
			marker = "x"
		}
		fmt.Fprintf(out, "  [%s] %d. %s\n", marker, index+1, name)
	}
	fmt.Fprintf(out, "\nRetentionOps may analyse only what you choose here. This authorisation is stored\n"+
		"on this server, and RetentionOps Cloud can neither read it nor widen it.\n")
	fmt.Fprintf(out, "\nNumbers to allow, separated by commas [%s]: ", strings.Join(current, ","))

	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	chosen, err := selectSchemas(strings.TrimSpace(answer), reachable, current)
	if err != nil {
		return err
	}

	backup, err := scope.Set(path, configuration, sourceID, chosen, reachable)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nAllowed: %s\n", strings.Join(chosen, ", "))
	fmt.Fprintf(out, "Written to %s. The previous file is kept at %s.\n", path, backup)
	fmt.Fprintln(out, "Restart the connector to load it, then run the schema analysis from the console.")
	return nil
}

// selectSchemas turns the operator's answer into names, refusing anything it cannot read.
//
// An unparseable answer keeps the current scope rather than guessing at one: this is the list that
// decides what a connector may look at, and "1,2" mistyped as "1.2" must not silently allow a
// schema nobody chose.
func selectSchemas(answer string, reachable, current []string) ([]string, error) {
	if answer == "" {
		if len(current) == 0 {
			return nil, errors.New("choose at least one schema, or this connector can reach nothing")
		}
		return append([]string(nil), current...), nil
	}
	chosen := []string{}
	for _, field := range strings.Split(answer, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		index, err := strconv.Atoi(field)
		if err != nil || index < 1 || index > len(reachable) {
			return nil, fmt.Errorf("%q is not one of the numbers above", field)
		}
		chosen = append(chosen, reachable[index-1])
	}
	if len(chosen) == 0 {
		return nil, errors.New("choose at least one schema, or this connector can reach nothing")
	}
	return chosen, nil
}
