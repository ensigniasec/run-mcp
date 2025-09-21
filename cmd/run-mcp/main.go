package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ensigniasec/run-mcp/internal/allowlist"
	api "github.com/ensigniasec/run-mcp/internal/api"
	"github.com/ensigniasec/run-mcp/internal/scanner"
	"github.com/ensigniasec/run-mcp/internal/storage"
	"github.com/ensigniasec/run-mcp/internal/tui"
	"github.com/ensigniasec/run-mcp/internal/validate"
)

//nolint:gochecknoglobals // Cobra requires package-level vars for flag bindings in current structure.
var (
	// Version metadata populated at build time via -ldflags.
	releaseVersion = "dev"
	commit         = "none"
	date           = "unknown"

	// Used for flags.
	storageFile = "~/Library/Application Support/run-mcp/results.json" // hardcoded default storage path. wiring for --storage-file flag left in place in case we care to add it back.
	verbose     bool
	jsonOutput  bool
	offline     bool
	orgUUID     string
	anonymous   bool
	tuiMode     bool

	rootCmd = &cobra.Command{
		Use:   "run-mcp",
		Short: "A fast, portable, single-binary security scanner for local the Model Context Protocol (MCP) config files.",
		Long:  `This tool discovers MCP configuration files and returns a security rating for each discovered MCP Server. It also detects security misconfigurations (i.e. long-lived secrets) and provides a gentle, client-side only way to apply security allow/deny rules for your MCP configurations.`,
	}
)

//nolint:gochecknoinits // Cobra command wiring performed in init in current structure.
func init() {
	// Route logs to stderr to avoid polluting stdout, especially for --json output.
	logrus.SetOutput(os.Stderr)

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable detailed logging output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format instead of rich text")
	rootCmd.PersistentFlags().BoolVar(&tuiMode, "tui", false, "Enable interactive TUI mode with real-time progress")
	rootCmd.PersistentFlags().
		BoolVar(&offline, "offline", false, "Optional: Run the scanner in offline mode, only outputs findings without security ratings")
	rootCmd.PersistentFlags().
		StringVar(&orgUUID, "org-uuid", "", "Optional: organization UUID for reporting")
	rootCmd.PersistentFlags().
		BoolVar(&anonymous, "anonymous", false, "Optional: Do not send any UUIDs or tracking information")
	// Alias for --anonymous
	rootCmd.PersistentFlags().BoolVar(&anonymous, "anon", false, "Alias of --anonymous")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(experimentalCmd)
	rootCmd.AddCommand(orgCmd)

	allowlistCmd.AddCommand(allowlistAddCmd)
	allowlistCmd.AddCommand(allowlistResetCmd)
	experimentalCmd.AddCommand(allowlistCmd)

	// Wire up experimental subcommands.
	experimentalCmd.AddCommand(experimentalInspectCmd)
	experimentalCmd.AddCommand(experimentalProxyCmd)
	experimentalCmd.AddCommand(experimentalDeepScanCmd)

	// Wire up org subcommands.
	orgCmd.AddCommand(orgRegisterCmd)
	orgCmd.AddCommand(orgClearCmd)
	orgCmd.AddCommand(orgShowCmd)

	// Built-in version flag: set version string and a custom template.
	rootCmd.Version = releaseVersion
	rootCmd.Annotations = map[string]string{"commit": commit, "date": date}
	rootCmd.SetVersionTemplate("{{printf \"%s %s\\ncommit: %s\\ndate: %s\\n\" .DisplayName .Version (index .Annotations \"commit\") (index .Annotations \"date\")}}")

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var scanCmd = &cobra.Command{
	Use:   "scan [CONFIG_FILE...]",
	Short: "Scan one or more MCP config files. [Defaults to well-known locations]",
	Long:  "Scan one or more MCP configuration files for security issues. If no files are specified, well-known config locations will be checked.",
	Run: func(cmd *cobra.Command, args []string) {
		// Check for conflicting flags
		if jsonOutput && tuiMode {
			logrus.Fatal("Cannot use --json and --tui flags together")
		}

		// Set log level based on flags
		if (jsonOutput || tuiMode) && !verbose {
			logrus.SetLevel(logrus.WarnLevel)
		} else if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		// Default to scanning well-known paths if no arguments are provided.
		if len(args) == 0 {
			args = scanner.GetWellKnownMCPPaths()
		}
		// Resolve host identity from storage, creating new storage if none exists yet.
		st, err := storage.NewOrExistingStorage(storageFile)
		if err != nil {
			logrus.Fatalf("Unable to open or create storage: %v", err)
		}

		// If not anonymous, build optional Identity for attaching to requests.
		ctx := cmd.Context()
		if !anonymous {
			if orgUUID == "" {
				orgUUID = st.Data.OrgUUID
			}
			hostUUID := st.Data.HostUUID
			ctx = api.WithIdentity(ctx, api.Identity{OrgUUID: orgUUID, HostUUID: hostUUID})
		}

		// Create RatingsCollector first with no client to allow immediate TUI launch.
		rc := scanner.NewRatingsCollector(ctx, nil, st)
		// Start the scan of local files
		s := scanner.NewMCPScanner(args, storageFile).WithRatingsCollector(rc)

		// If online mode, initialize API client in the background and attach to collector when ready.
		if !offline {
			go func() {
				opts := []api.ClientOption{}
				if cl, err := api.NewClient(opts...); err == nil {
					rc.SetClient(cl)
				} else if errors.Is(err, api.ErrOffline) {
					logrus.Debug("remote health unavailable; continuing in offline mode")
				} else {
					logrus.Debugf("api client init failed: %v", err)
				}
			}()
		}

		// Choose output mode BEFORE scanning for real-time streaming
		if tuiMode {
			// Run TUI mode with real-time streaming
			if err := tui.Run(ctx, args, s, rc); err != nil {
				logrus.Fatalf("TUI mode failed: %v", err)
			}
		} else {
			// Traditional mode - scan then display results
			result, err := s.Scan()
			if err != nil {
				logrus.Fatal(err)
			}

			summary := scanner.GenerateSummary(*result)
			// Apply any policies/ratings gathered during scanning.
			rc.ApplyToSummary(&summary)
			// Ensure any pending batches are flushed and workers stopped before printing.
			rc.FlushAndStop()
			scanner.PrintSummary(summary, jsonOutput)
		}

		/*
			TODO:
			- refresh ratings from storage if available
		*/
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure
var allowlistCmd = &cobra.Command{
	Use:   "allowlist",
	Short: "Manage the local allowlist of approved entities",
	Long:  "View, add, or reset local allowlisted entities. Allowlisted entities bypass security checks during scans.",
	Run: func(cmd *cobra.Command, args []string) {
		v, err := allowlist.NewVerifier(storageFile)
		if err != nil {
			logrus.Fatal(err)
		}
		v.ViewAllowlist(os.Stdout)
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var allowlistAddCmd = &cobra.Command{
	Use:   "add [TYPE] [NAME] [HASH]",
	Short: "Add an entity to the local allowlist",
	Long:  "Add a MCP Server to the local allowlist.",
	Args:  cobra.ExactArgs(3), //nolint:mnd // Allowlist 'add' requires exactly 3 arguments by CLI contract
	Run: func(cmd *cobra.Command, args []string) {
		v, err := allowlist.NewVerifier(storageFile)
		if err != nil {
			logrus.Fatal(err)
		}
		if err := v.AddToAllowlist(args[0], args[1], args[2]); err != nil {
			logrus.Fatal(err)
		}
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var allowlistResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset the local allowlist",
	Long:  "Reset the entire local allowlist.",
	Run: func(cmd *cobra.Command, args []string) {
		v, err := allowlist.NewVerifier(storageFile)
		if err != nil {
			logrus.Fatal(err)
		}
		if err := v.ResetAllowlist(); err != nil {
			logrus.Fatal(err)
		}
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var experimentalCmd = &cobra.Command{
	Use:   "experimental",
	Short: "Experimental features (subject to change).",
	Long:  "A collection of experimental commands that may change or be removed without notice.",
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var experimentalInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Actively enumerates a given MCP Server to discover tool calls (experimental).",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(
			os.Stdout,
			"This command is under construction. Thanks for your interest. Please let Frenchie know if this would be useful for you!",
		)
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var experimentalProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Proxy tool_calls to/from this MCP server (experimental).",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(
			os.Stdout,
			"This command is under construction. Thanks for your interest. Please let Frenchie know if this would be useful for you!",
		)
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var experimentalDeepScanCmd = &cobra.Command{
	Use:   "deep-scan",
	Short: "Scan entire filesystem to match on all MCP configs (experimental).",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(
			os.Stdout,
			"This command is under construction. Thanks for your interest. Please let Frenchie know if this would be useful for you!",
		)
	},
}

func main() {
	Execute()
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Manage organization identity settings",
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var orgRegisterCmd = &cobra.Command{
	Use:   "register [UUID]",
	Short: "Register and persist an organization UUID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		s, err := storage.NewOrExistingStorage(storageFile)
		if err != nil {
			logrus.Fatal(err)
		}
		if err := validate.Var(args[0], "uuid_rfc4122"); err != nil {
			logrus.Fatalf(
				"Invalid organization UUID: %q. Expected an RFC 4122 UUID (example: 123e4567-e89b-12d3-a456-426614174000).",
				args[0],
			)
		}
		s.Data.OrgUUID = args[0]
		if err := s.Save(); err != nil {
			logrus.Fatal(err)
		}
		fmt.Fprintf(os.Stdout, "Organization UUID set to %s\n", s.Data.OrgUUID)
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var orgClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the persisted organization UUID",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := storage.NewOrExistingStorage(storageFile)
		if err != nil {
			logrus.Fatal(err)
		}
		s.Data.OrgUUID = ""
		if err := s.Save(); err != nil {
			logrus.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, "Organization UUID cleared")
	},
}

//nolint:gochecknoglobals // Cobra command is defined at package scope in current structure.
var orgShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current organization UUID (if any)",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := storage.NewOrExistingStorage(storageFile)
		if err != nil {
			logrus.Fatal(err)
		}
		if s.Data.OrgUUID == "" {
			fmt.Fprintln(os.Stdout, "No organization UUID set")
			return
		}
		fmt.Fprintf(os.Stdout, "%s\n", s.Data.OrgUUID)
	},
}
