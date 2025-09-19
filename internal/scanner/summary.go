package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ScanSummary provides a high-level summary of scan results.
type ScanSummary struct {
	Servers          []ServerReport  `json:"Servers"`
	Secrets          []SecretFinding `json:"Secrets"`
	TotalServers     int             `json:"TotalServers"`
	TotalFindings    int             `json:"TotalFindings"`
	CriticalFindings int             `json:"CriticalFindings"`
	HighFindings     int             `json:"HighFindings"`
	MediumFindings   int             `json:"MediumFindings"`
	LowFindings      int             `json:"LowFindings"`
	StartedAt        time.Time       `json:"StartedAt"`
	Duration         time.Duration   `json:"Duration"`
	ScannedFiles     int             `json:"ScannedFiles"`
}

func NewScanSummary(result ScanResult) ScanSummary {
	summary := new(ScanSummary)
	summary.Servers = []ServerReport{}
	summary.Secrets = []SecretFinding{}
	summary.StartedAt = result.StartedAt
	summary.Duration = result.Duration
	summary.ScannedFiles = len(result.Files)
	return *summary
}

func NewServerReport(name string, path string, secrets []SecretFinding, localPolicy string) ServerReport {
	sr := new(ServerReport)
	sr.Name = name
	sr.Path = path
	sr.Secrets = secrets
	sr.LocalPolicy = localPolicy
	return *sr
}

// GenerateSummary analyzes a single aggregated scan result and creates a summary.
func GenerateSummary(result ScanResult) ScanSummary {
	summary := NewScanSummary(result)

	for _, file := range result.Files {
		// Index secrets by server name for this file.
		secretsByName := make(map[string][]SecretFinding)
		for _, s := range file.SecretFindings {
			// Collect for global secrets section.
			summary.Secrets = append(summary.Secrets, s)
			// Associate to server for per-server context (not used for risk grouping).
			secretsByName[s.ServerName] = append(secretsByName[s.ServerName], s)
			// Count severity now.
			summary.TotalFindings++
		}
		for _, server := range file.Servers {
			summary.TotalServers++
			sr := ServerReport{
				Name:        server.Name,
				Path:        file.Path,
				Secrets:     secretsByName[server.Name],
				LocalPolicy: "", // TODO: figure out how this gets applied
				Rating:      nil,
			}
			summary.Servers = append(summary.Servers, sr)
		}
	}

	return summary
}

// PrintSummary outputs the results in the requested format.
// If jsonOutput is true, it prints machine-readable JSON of the full results.
// Otherwise, it prints a human-readable summary with ratings and recommendations.
//
//nolint:gocognit,gocyclo,cyclop,funlen // Verbose CLI rendering for readability; refactor deferred.
func PrintSummary(summary ScanSummary, jsonOutput bool) {
	if jsonOutput {
		output, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Fprintln(os.Stdout, string(output))
		return
	}

	printRunMCPBanner()

	fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
	fmt.Fprintln(os.Stdout, "RUN-MCP SCAN REPORT")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
	fmt.Fprintf(os.Stdout, "Scan Time: %s\n", summary.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(
		os.Stdout,
		"Scanned: %d files, %d servers detected (duration: %s)\n",
		summary.ScannedFiles,
		summary.TotalServers,
		HumanDuration(summary.Duration),
	)

	// Group servers by status and risk tiers.
	critical, high, medium, low := []ServerReport{}, []ServerReport{}, []ServerReport{}, []ServerReport{}
	allowed, denied, pending, discovered := []ServerReport{}, []ServerReport{}, []ServerReport{}, []ServerReport{}
	for _, s := range summary.Servers {
		// Explicit local policies first.
		switch s.LocalPolicy {
		case "allowed":
			allowed = append(allowed, s)
			continue
		case "denied":
			denied = append(denied, s)
			continue
		case "pending":
			// Explicitly queued/accepted for processing.
			pending = append(pending, s)
			continue
		}
		// If rated, bucket by severity; otherwise treat as discovered/unknown.
		if s.Rating != nil {
			switch riskTierFromScore(s.Rating.RiskScore) {
			case "CRITICAL":
				critical = append(critical, s)
			case "HIGH":
				high = append(high, s)
			case "MEDIUM":
				medium = append(medium, s)
			case "LOW":
				low = append(low, s)
			}
			continue
		}
		// Not rated and no explicit policy => discovered (not submitted/unknown).
		discovered = append(discovered, s)
	}

	// Risk summary (computed from current buckets).
	fmt.Fprintf(os.Stdout, "\n📊 RISK SUMMARY\n")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
	if len(critical) > 0 {
		fmt.Fprintf(os.Stdout, "   🔴 Critical Risk : %d servers\n", len(critical))
	}
	if len(high) > 0 {
		fmt.Fprintf(os.Stdout, "   🟠 High Risk     : %d servers\n", len(high))
	}
	if len(medium) > 0 {
		fmt.Fprintf(os.Stdout, "   🟡 Medium Risk   : %d servers\n", len(medium))
	}
	if len(low) > 0 {
		fmt.Fprintf(os.Stdout, "   🟢 Low Risk      : %d servers\n", len(low))
	}
	if len(pending) > 0 {
		fmt.Fprintf(os.Stdout, "   ⏳ Pending       : %d servers\n", len(pending))
	}
	if len(discovered) > 0 {
		fmt.Fprintf(os.Stdout, "   🔎 Discovered    : %d servers\n", len(discovered))
	}
	if len(allowed) > 0 {
		fmt.Fprintf(os.Stdout, "   ✅ Allowed       : %d servers\n", len(allowed))
	}
	if len(denied) > 0 {
		fmt.Fprintf(os.Stdout, "   ⛔ Denied        : %d servers\n", len(denied))
	}
	if len(summary.Secrets) > 0 {
		fmt.Fprintf(os.Stdout, "   ☢️ Exposed secrets: %d\n", len(summary.Secrets))
	}

	// Print Critical
	if len(critical) > 0 {
		fmt.Fprintf(os.Stdout, "\n🚨 CRITICAL FINDINGS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range critical {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			if server.Rating != nil {
				fmt.Fprintf(
					os.Stdout,
					"    Risk Score: %.1f/10 - %s\n",
					server.Rating.RiskScore,
					server.Rating.Category,
				)
				if server.Rating.Version != "" {
					fmt.Fprintf(os.Stdout, "    Source: %s@%s\n", server.Rating.Name, server.Rating.Version)
				}
				if len(server.Rating.Vulnerabilities) > 0 {
					fmt.Fprintf(os.Stdout, "    \n    ⚠️  Detected Issues:\n")
					for _, vuln := range server.Rating.Vulnerabilities {
						fmt.Fprintf(os.Stdout, "    • %s\n", vuln)
					}
				}
			}
			count++
		}
	}

	// High
	if len(high) > 0 {
		fmt.Fprintf(os.Stdout, "\n🟠 HIGH RISK FINDINGS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range high {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			if server.Rating != nil {
				fmt.Fprintf(
					os.Stdout,
					"    Risk Score: %.1f/10 - %s\n",
					server.Rating.RiskScore,
					server.Rating.Category,
				)
				if server.Rating.Version != "" {
					fmt.Fprintf(os.Stdout, "    Source: %s@%s\n", server.Rating.Name, server.Rating.Version)
				}
				if len(server.Rating.Vulnerabilities) > 0 {
					fmt.Fprintf(os.Stdout, "    \n    ⚠️  Detected Issues:\n")
					for _, vuln := range server.Rating.Vulnerabilities {
						fmt.Fprintf(os.Stdout, "    • %s\n", vuln)
					}
				}
			}
			count++
		}
	}

	if len(medium) > 0 {
		fmt.Fprintf(os.Stdout, "\n🟡 MEDIUM RISK FINDINGS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range medium {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			if server.Rating != nil {
				fmt.Fprintf(
					os.Stdout,
					"    Risk Score: %.1f/10 - %s\n",
					server.Rating.RiskScore,
					server.Rating.Category,
				)
			}
			count++
		}
	}

	// Low
	if len(low) > 0 {
		fmt.Fprintf(os.Stdout, "\n🟢 LOW RISK FINDINGS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range low {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			if server.Rating != nil {
				fmt.Fprintf(
					os.Stdout,
					"    Risk Score: %.1f/10 - %s\n",
					server.Rating.RiskScore,
					server.Rating.Category,
				)
			}
			count++
		}
	}

	// Allowed servers
	if len(allowed) > 0 {
		fmt.Fprintf(os.Stdout, "\n✅ ALLOWED SERVERS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range allowed {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			count++
		}
	}

	// Denied servers
	if len(denied) > 0 {
		fmt.Fprintf(os.Stdout, "\n⛔ DENIED SERVERS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range denied {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			count++
		}
	}

	// Pending servers
	if len(pending) > 0 {
		fmt.Fprintf(os.Stdout, "\n⏳ PENDING RATING\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range pending {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			count++
		}
	}

	// Discovered servers
	if len(discovered) > 0 {
		fmt.Fprintf(os.Stdout, "\n🔎 DISCOVERED (NOT SUBMITTED - OFFLINE MODE)\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		count := 1
		for _, server := range discovered {
			fmt.Fprintf(os.Stdout, "\n[%d] Server: \"%s\" (%s)\n", count, server.Name, server.Path)
			count++
		}
	}

	// Exposed secrets (if any)
	if len(summary.Secrets) > 0 {
		fmt.Fprintf(os.Stdout, "\n🔐 EXPOSED SECRETS\n")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
		for _, s := range summary.Secrets {
			if s.Key != "" {
				fmt.Fprintf(os.Stdout, "    • [%s] %s: %s = \"%s\"", s.ServerName, s.Kind, s.Key, s.Value)
			} else {
				fmt.Fprintf(os.Stdout, "    • [%s] %s: \"%s\"", s.ServerName, s.Kind, s.Value)
			}
			if len(s.Occurrences) > 0 {
				// Print first file:line and count of the rest.
				var shown string
				var extra int
				for file, lines := range s.Occurrences {
					if len(lines) == 0 {
						shown = file
					} else {
						shown = fmt.Sprintf("%s:%d", file, lines[0])
						extra += len(lines) - 1
					}
					// Count remaining files and lines
					for f2, lines2 := range s.Occurrences {
						if f2 == file {
							continue
						}
						if len(lines2) == 0 {
							extra++
						} else {
							extra += len(lines2)
						}
					}
					break
				}
				if extra > 0 {
					fmt.Fprintf(os.Stdout, " (path: %s +%d more)", shown, extra)
				} else {
					fmt.Fprintf(os.Stdout, " (path: %s)", shown)
				}
			}
			fmt.Fprintln(os.Stdout)
		}
	}

	// Recommendations
	fmt.Fprintf(os.Stdout, "\n💡 SECURITY RECOMMENDATIONS\n")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))

	if (summary.CriticalFindings > 0 || summary.HighFindings > 0) || len(summary.Secrets) > 0 {
		fmt.Fprintln(os.Stdout, "\nIMMEDIATE ACTIONS:")
		if summary.CriticalFindings > 0 {
			fmt.Fprintf(os.Stdout, "1. Remove %d malicious servers identified above\n", summary.CriticalFindings)
		}
		if len(summary.Secrets) > 0 {
			fmt.Fprintf(os.Stdout, "2. Rotate %d exposed credentials:\n", len(summary.Secrets))
			for _, secret := range summary.Secrets {
				fmt.Fprintf(os.Stdout, "   - %s (used by %s)\n", secret.Kind, secret.ServerName)
			}
		}
	}
	PrintFooter()
}

const reportWidth = 80

func PrintFooter() {
	fmt.Fprintf(os.Stdout, "\nRun 'run-mcp scan --json' for detailed output\n")
	// fmt.Fprintf(os.Stdout, "\nRun 'run-mcp scan --poll' with polling if you received results with status 'QUEUED_FOR_PROCESSING'\n") // TODO: add this back in once we have polling
	fmt.Fprintf(os.Stdout, "Run 'run-mcp experimental allowlist add' to approve allowed servers\n")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", reportWidth))
}

// HumanDuration returns a compact, human-readable duration string.
// Examples: 850ms, 1.23s, 2m05s, 1h02m.
func HumanDuration(d time.Duration) string {
	if d < time.Millisecond {
		us := d / time.Microsecond
		return fmt.Sprintf("%dµs", us)
	}
	if d < time.Second {
		ms := d / time.Millisecond
		return fmt.Sprintf("%dms", ms)
	}
	if d < time.Minute {
		secs := float64(d) / float64(time.Second)
		return fmt.Sprintf("%.2fs", secs)
	}
	if d < time.Hour {
		m := d / time.Minute
		s := (d % time.Minute) / time.Second
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	return fmt.Sprintf("%dh%02dm", h, m)
}

// riskTierFromScore converts a 0-10 risk score into a tier label.
//
//nolint:mnd // score is self-documenting
func riskTierFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "NONE"
	}
}

// PrintRunMCPBanner renders a RUN-MCP banner.
func printRunMCPBanner() {
	fmt.Fprint(os.Stdout, runMCPBanner())
}

// RunMCPBanner returns the RUN-MCP banner ANSI art as a string.
func runMCPBanner() string {
	return "\x1b[38;2;2;2;6;48;2;2;3;0m▄\x1b[38;2;143;26;53;48;2;17;0;5m▄\x1b[38;2;171;14;44;48;2;3;3;7m▄\x1b[38;2;184;12;46;48;2;4;2;0m▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\x1b[38;2;149;28;53;48;2;10;3;0m▄\x1b[38;2;0;8;0;48;2;3;2;0m▄\x1b[m\n" +
		"\x1b[38;2;0;12;0;48;2;6;0;4m▄\x1b[38;2;148;26;46;48;2;154;23;44m▄\x1b[38;2;188;7;37;48;2;181;13;27m▄\x1b[38;2;183;11;30;48;2;179;18;35m▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\x1b[38;2;172;16;53;48;2;169;17;53m▄\x1b[38;2;0;3;0;48;2;0;9;0m▄\x1b[m\n" +
		"\x1b[38;2;2;2;2;48;2;8;0;1m▄\x1b[38;2;2;2;2;48;2;117;20;43m▄\x1b[38;2;2;2;2;48;2;129;15;35m▄\x1b[38;2;15;15;15;48;2;134;14;31m▄\x1b[38;2;10;10;10;48;2;134;14;31m▄▄▄▄\x1b[38;2;1;1;1;48;2;134;14;31m▄\x1b[38;2;0;0;0;48;2;134;14;31m▄▄\x1b[38;2;7;7;7;48;2;134;14;31m▄\x1b[38;2;13;13;13;48;2;134;14;31m▄\x1b[38;2;2;2;2;48;2;134;14;31m▄▄▄▄▄\x1b[38;2;10;10;10;48;2;134;14;31m▄▄▄\x1b[38;2;2;2;2;48;2;134;14;31m▄▄▄▄▄\x1b[38;2;5;5;5;48;2;134;14;31m▄\x1b[38;2;8;8;8;48;2;134;14;31m▄\x1b[38;2;10;10;10;48;2;134;14;31m▄▄▄\x1b[38;2;2;2;2;48;2;134;14;31m▄▄\x1b[38;2;5;5;5;48;2;134;14;31m▄\x1b[38;2;10;10;10;48;2;134;14;31m▄▄▄\x1b[38;2;7;7;7;48;2;134;14;31m▄\x1b[38;2;2;2;2;48;2;134;14;31m▄▄▄▄\x1b[38;2;11;11;11;48;2;134;14;31m▄\x1b[38;2;10;10;10;48;2;134;14;31m▄▄▄\x1b[38;2;2;2;2;48;2;134;14;31m▄\x1b[38;2;2;2;2;48;2;100;31;38m▄\x1b[38;2;2;2;2;48;2;1;3;0m▄\x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[38;2;240;240;240;48;2;241;241;241m▄\x1b[48;2;255;255;255m    \x1b[38;2;255;255;255;48;2;248;248;248m▄\x1b[38;2;255;255;255;48;2;253;253;253m▄\x1b[38;2;255;255;255;48;2;252;252;252m▄\x1b[38;2;255;255;255;48;2;248;248;248m▄\x1b[38;2;255;255;255;48;2;233;233;233m▄\x1b[38;2;254;254;254;48;2;2;2;2m▄\x1b[38;2;91;91;91;48;2;1;1;1m▄\x1b[38;2;1;1;1;48;2;3;3;3m▄\x1b[48;2;2;2;2m \x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;248;248;248m \x1b[48;2;2;2;2m    \x1b[38;2;3;3;3;48;2;9;9;9m▄\x1b[48;2;254;254;254m \x1b[48;2;255;255;255m  \x1b[38;2;255;255;255;48;2;253;253;253m▄\x1b[48;2;2;2;2m  \x1b[38;2;55;55;55;48;2;61;61;61m▄\x1b[48;2;255;255;255m   \x1b[38;2;245;245;245;48;2;249;249;249m▄\x1b[38;2;12;12;12;48;2;7;7;7m▄\x1b[48;2;2;2;2m   \x1b[38;2;32;32;32;48;2;43;43;43m▄\x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;240;240;240m \x1b[48;2;255;255;255m  \x1b[38;2;255;255;255;48;2;254;254;254m▄\x1b[48;2;2;2;2m \x1b[38;2;2;2;2;48;2;4;4;4m▄\x1b[38;2;2;2;2;48;2;1;1;1m▄\x1b[38;2;1;1;1;48;2;97;97;97m▄\x1b[38;2;208;208;208;48;2;244;244;244m▄\x1b[48;2;255;255;255m  \x1b[38;2;251;251;251;48;2;254;254;254m▄\x1b[38;2;0;0;0;48;2;5;5;5m▄\x1b[48;2;2;2;2m \x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;248;248;248m \x1b[48;2;2;2;2m    \x1b[48;2;3;3;3m \x1b[48;2;254;254;254m \x1b[48;2;255;255;255m   \x1b[48;2;2;2;2m  \x1b[48;2;55;55;55m \x1b[48;2;255;255;255m   \x1b[38;2;245;245;245;48;2;255;255;255m▄\x1b[38;2;255;255;255;48;2;250;250;250m▄\x1b[38;2;17;17;17;48;2;2;2;2m▄\x1b[38;2;0;0;0;48;2;2;2;2m▄\x1b[48;2;2;2;2m \x1b[48;2;32;32;32m \x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;240;240;240m \x1b[48;2;255;255;255m   \x1b[48;2;2;2;2m  \x1b[48;2;0;0;0m \x1b[38;2;39;39;39;48;2;11;11;11m▄\x1b[38;2;236;236;236;48;2;196;196;196m▄\x1b[48;2;255;255;255m  \x1b[38;2;251;251;251;48;2;253;253;253m▄\x1b[38;2;1;1;1;48;2;5;5;5m▄\x1b[48;2;2;2;2m \x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;248;248;248m \x1b[48;2;2;2;2m    \x1b[48;2;3;3;3m \x1b[48;2;254;254;254m \x1b[48;2;255;255;255m   \x1b[48;2;2;2;2m  \x1b[48;2;55;55;55m \x1b[48;2;255;255;255m   \x1b[38;2;4;4;4;48;2;254;254;254m▄\x1b[48;2;255;255;255m \x1b[38;2;253;253;253;48;2;249;249;249m▄\x1b[38;2;50;50;50;48;2;1;1;1m▄\x1b[48;2;2;2;2m \x1b[48;2;32;32;32m \x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;240;240;240m \x1b[48;2;255;255;255m  \x1b[48;2;254;254;254m \x1b[38;2;252;252;252;48;2;254;254;254m▄\x1b[38;2;250;250;250;48;2;254;254;254m▄\x1b[38;2;255;255;255;48;2;254;254;254m▄▄\x1b[48;2;255;255;255m \x1b[38;2;151;151;151;48;2;251;251;251m▄\x1b[38;2;9;9;9;48;2;242;242;242m▄\x1b[38;2;2;2;2;48;2;4;4;4m▄\x1b[38;2;2;2;2;48;2;3;3;3m▄\x1b[48;2;2;2;2m \x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;248;248;248m \x1b[48;2;2;2;2m    \x1b[48;2;3;3;3m \x1b[48;2;254;254;254m \x1b[48;2;255;255;255m   \x1b[48;2;2;2;2m  \x1b[48;2;55;55;55m \x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[38;2;2;2;2;48;2;253;253;253m▄\x1b[48;2;255;255;255m \x1b[38;2;255;255;255;48;2;252;252;252m▄\x1b[38;2;58;58;58;48;2;8;8;8m▄\x1b[38;2;28;28;28;48;2;32;32;32m▄\x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;240;240;240m \x1b[48;2;255;255;255m   \x1b[48;2;2;2;2m \x1b[38;2;5;5;5;48;2;3;3;3m▄\x1b[38;2;4;4;4;48;2;222;222;222m▄\x1b[38;2;243;243;243;48;2;253;253;253m▄\x1b[48;2;255;255;255m  \x1b[38;2;252;252;252;48;2;85;85;85m▄\x1b[48;2;2;2;2m   \x1b[38;2;8;8;8;48;2;6;6;6m▄\x1b[48;2;255;255;255m   \x1b[48;2;244;244;244m \x1b[48;2;2;2;2m    \x1b[48;2;5;5;5m \x1b[48;2;255;255;255m   \x1b[38;2;249;249;249;48;2;242;242;242m▄\x1b[48;2;2;2;2m  \x1b[48;2;55;55;55m \x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m \x1b[38;2;5;5;5;48;2;239;239;239m▄\x1b[38;2;252;252;252;48;2;253;253;253m▄\x1b[48;2;255;255;255m \x1b[38;2;106;106;106;48;2;34;34;34m▄\x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;240;240;240m \x1b[48;2;255;255;255m   \x1b[48;2;2;2;2m   \x1b[38;2;0;0;0;48;2;9;9;9m▄\x1b[38;2;86;86;86;48;2;254;254;254m▄\x1b[38;2;253;253;253;48;2;255;255;255m▄\x1b[38;2;255;255;255;48;2;254;254;254m▄\x1b[38;2;254;254;254;48;2;244;244;244m▄\x1b[38;2;112;112;112;48;2;5;5;5m▄\x1b[38;2;3;3;3;48;2;2;2;2m▄\x1b[48;2;2;2;2m \x1b[38;2;5;5;5;48;2;175;175;175m▄\x1b[38;2;251;251;251;48;2;250;250;250m▄\x1b[48;2;255;255;255m \x1b[38;2;255;255;255;48;2;251;251;251m▄\x1b[38;2;252;252;252;48;2;16;16;16m▄\x1b[38;2;240;240;240;48;2;2;2;2m▄\x1b[38;2;194;194;194;48;2;2;2;2m▄\x1b[38;2;239;239;239;48;2;2;2;2m▄\x1b[38;2;255;255;255;48;2;6;6;6m▄\x1b[38;2;255;255;255;48;2;254;254;254m▄\x1b[48;2;255;255;255m \x1b[38;2;254;254;254;48;2;255;255;255m▄\x1b[38;2;0;0;0;48;2;173;173;173m▄\x1b[48;2;2;2;2m  \x1b[48;2;55;55;55m \x1b[48;2;255;255;255m   \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m \x1b[38;2;2;2;2;48;2;19;19;19m▄\x1b[38;2;1;1;1;48;2;226;226;226m▄\x1b[38;2;248;248;248;48;2;255;255;255m▄\x1b[48;2;255;255;255m    \x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[38;2;222;222;222;48;2;240;240;240m▄\x1b[38;2;215;215;215;48;2;253;253;253m▄▄\x1b[38;2;218;218;218;48;2;254;254;254m▄\x1b[38;2;4;4;4;48;2;1;1;1m▄\x1b[48;2;2;2;2m    \x1b[38;2;12;12;12;48;2;252;252;252m▄\x1b[38;2;215;215;215;48;2;253;253;253m▄▄▄\x1b[38;2;215;215;215;48;2;1;1;1m▄\x1b[48;2;2;2;2m \x1b[38;2;0;0;0;48;2;5;5;5m▄\x1b[38;2;1;1;1;48;2;66;66;66m▄\x1b[38;2;8;8;8;48;2;234;234;234m▄\x1b[38;2;100;100;100;48;2;253;253;253m▄\x1b[48;2;255;255;255m    \x1b[38;2;254;254;254;48;2;253;253;253m▄\x1b[38;2;83;83;83;48;2;254;254;254m▄\x1b[38;2;5;5;5;48;2;255;255;255m▄\x1b[38;2;30;30;30;48;2;67;67;67m▄\x1b[48;2;2;2;2m   \x1b[38;2;48;48;48;48;2;54;54;54m▄\x1b[38;2;215;215;215;48;2;253;253;253m▄▄▄\x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[48;2;1;1;1m \x1b[38;2;4;4;4;48;2;202;202;202m▄\x1b[38;2;209;209;209;48;2;249;249;249m▄\x1b[38;2;215;215;215;48;2;253;253;253m▄▄▄\x1b[48;2;0;0;0m \x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[38;2;253;253;253;48;2;0;0;0m▄\x1b[38;2;255;255;255;48;2;2;2;2m▄▄\x1b[38;2;254;254;254;48;2;2;2;2m▄\x1b[38;2;23;23;23;48;2;0;0;0m▄\x1b[48;2;2;2;2m  \x1b[38;2;9;9;9;48;2;0;0;0m▄\x1b[38;2;249;249;249;48;2;1;1;1m▄\x1b[38;2;255;255;255;48;2;0;0;0m▄\x1b[38;2;255;255;255;48;2;2;2;2m▄▄▄\x1b[38;2;2;2;2;48;2;0;0;0m▄\x1b[48;2;2;2;2m    \x1b[38;2;11;11;11;48;2;0;0;0m▄\x1b[38;2;240;240;240;48;2;5;5;5m▄\x1b[38;2;248;248;248;48;2;10;10;10m▄\x1b[38;2;255;255;255;48;2;9;9;9m▄\x1b[38;2;255;255;255;48;2;18;18;18m▄\x1b[38;2;255;255;255;48;2;17;17;17m▄\x1b[38;2;255;255;255;48;2;12;12;12m▄\x1b[38;2;255;255;255;48;2;1;1;1m▄\x1b[38;2;229;229;229;48;2;0;0;0m▄\x1b[38;2;3;3;3;48;2;2;2;2m▄\x1b[48;2;2;2;2m   \x1b[38;2;248;248;248;48;2;4;4;4m▄\x1b[38;2;255;255;255;48;2;2;2;2m▄▄\x1b[38;2;255;255;255;48;2;0;0;0m▄▄▄\x1b[38;2;253;253;253;48;2;0;0;0m▄\x1b[38;2;240;240;240;48;2;2;2;2m▄\x1b[38;2;252;252;252;48;2;0;0;0m▄\x1b[38;2;205;205;205;48;2;3;3;3m▄\x1b[38;2;1;1;1;48;2;3;3;3m▄\x1b[38;2;5;5;5;48;2;3;3;3m▄\x1b[48;2;2;2;2m   \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;253;253;253m \x1b[48;2;255;255;255m \x1b[38;2;253;253;253;48;2;255;255;255m▄\x1b[48;2;255;255;255m \x1b[38;2;251;251;251;48;2;229;229;229m▄\x1b[38;2;7;7;7;48;2;1;1;1m▄\x1b[38;2;6;6;6;48;2;2;2;2m▄\x1b[38;2;132;132;132;48;2;0;0;0m▄\x1b[38;2;253;253;253;48;2;250;250;250m▄\x1b[38;2;250;250;250;48;2;255;255;255m▄\x1b[48;2;255;255;255m   \x1b[48;2;4;4;4m \x1b[48;2;2;2;2m   \x1b[38;2;255;255;255;48;2;22;22;22m▄\x1b[48;2;255;255;255m \x1b[38;2;251;251;251;48;2;255;255;255m▄▄\x1b[38;2;101;101;101;48;2;253;253;253m▄\x1b[38;2;0;0;0;48;2;252;252;252m▄\x1b[38;2;0;0;0;48;2;255;255;255m▄\x1b[38;2;6;6;6;48;2;248;248;248m▄\x1b[38;2;38;38;38;48;2;252;252;252m▄\x1b[38;2;252;252;252;48;2;250;250;250m▄\x1b[38;2;1;1;1;48;2;0;0;0m▄\x1b[48;2;2;2;2m   \x1b[48;2;246;246;246m \x1b[48;2;255;255;255m  \x1b[38;2;253;253;253;48;2;254;254;254m▄\x1b[38;2;2;2;2;48;2;252;252;252m▄\x1b[38;2;3;3;3;48;2;252;252;252m▄\x1b[38;2;3;3;3;48;2;253;253;253m▄\x1b[38;2;103;103;103;48;2;252;252;252m▄\x1b[38;2;252;252;252;48;2;255;255;255m▄\x1b[48;2;255;255;255m \x1b[38;2;255;255;255;48;2;240;240;240m▄\x1b[38;2;251;251;251;48;2;42;42;42m▄\x1b[38;2;5;5;5;48;2;1;1;1m▄\x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;253;253;253m \x1b[48;2;255;255;255m \x1b[38;2;255;255;255;48;2;247;247;247m▄\x1b[38;2;88;88;88;48;2;254;254;254m▄\x1b[38;2;250;250;250;48;2;255;255;255m▄\x1b[38;2;244;244;244;48;2;77;77;77m▄\x1b[48;2;1;1;1m \x1b[48;2;254;254;254m \x1b[38;2;255;255;255;48;2;251;251;251m▄\x1b[38;2;33;33;33;48;2;26;26;26m▄\x1b[48;2;255;255;255m   \x1b[48;2;4;4;4m \x1b[48;2;2;2;2m \x1b[38;2;6;6;6;48;2;0;0;0m▄\x1b[38;2;255;255;255;48;2;238;238;238m▄\x1b[48;2;255;255;255m  \x1b[38;2;252;252;252;48;2;255;255;255m▄\x1b[38;2;1;1;1;48;2;50;50;50m▄\x1b[38;2;2;2;2;48;2;12;12;12m▄\x1b[48;2;2;2;2m    \x1b[38;2;2;2;2;48;2;3;3;3m▄\x1b[38;2;2;2;2;48;2;1;1;1m▄\x1b[48;2;2;2;2m   \x1b[48;2;246;246;246m \x1b[48;2;255;255;255m  \x1b[48;2;253;253;253m \x1b[48;2;2;2;2m  \x1b[38;2;2;2;2;48;2;1;1;1m▄\x1b[48;2;2;2;2m \x1b[38;2;188;188;188;48;2;202;202;202m▄\x1b[48;2;255;255;255m   \x1b[38;2;3;3;3;48;2;2;2;2m▄\x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;253;253;253m \x1b[48;2;255;255;255m  \x1b[48;2;4;4;4m \x1b[38;2;239;239;239;48;2;247;247;247m▄\x1b[38;2;255;255;255;48;2;246;246;246m▄\x1b[38;2;254;254;254;48;2;170;170;170m▄\x1b[38;2;254;254;254;48;2;252;252;252m▄\x1b[38;2;41;41;41;48;2;254;254;254m▄\x1b[38;2;0;0;0;48;2;14;14;14m▄\x1b[48;2;255;255;255m   \x1b[48;2;4;4;4m \x1b[48;2;2;2;2m \x1b[38;2;9;9;9;48;2;10;10;10m▄\x1b[38;2;251;251;251;48;2;253;253;253m▄\x1b[48;2;255;255;255m  \x1b[38;2;187;187;187;48;2;226;226;226m▄\x1b[38;2;0;0;0;48;2;3;3;3m▄\x1b[48;2;2;2;2m          \x1b[48;2;246;246;246m \x1b[48;2;255;255;255m  \x1b[48;2;254;254;254m \x1b[38;2;254;254;254;48;2;0;0;0m▄▄\x1b[38;2;254;254;254;48;2;3;3;3m▄\x1b[38;2;254;254;254;48;2;1;1;1m▄\x1b[48;2;255;255;255m \x1b[38;2;254;254;254;48;2;255;255;255m▄\x1b[38;2;225;225;225;48;2;254;254;254m▄\x1b[38;2;169;169;169;48;2;252;252;252m▄\x1b[38;2;2;2;2;48;2;5;5;5m▄\x1b[48;2;2;2;2m  \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;253;253;253m \x1b[48;2;255;255;255m  \x1b[48;2;4;4;4m \x1b[38;2;0;0;0;48;2;92;92;92m▄\x1b[38;2;181;181;181;48;2;255;255;255m▄▄\x1b[38;2;170;170;170;48;2;255;255;255m▄\x1b[38;2;1;1;1;48;2;0;0;0m▄\x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;4;4;4m \x1b[48;2;2;2;2m \x1b[48;2;0;0;0m \x1b[38;2;253;253;253;48;2;248;248;248m▄\x1b[48;2;255;255;255m  \x1b[38;2;248;248;248;48;2;207;207;207m▄\x1b[38;2;0;0;0;48;2;3;3;3m▄\x1b[48;2;2;2;2m          \x1b[48;2;246;246;246m \x1b[48;2;255;255;255m  \x1b[38;2;254;254;254;48;2;255;255;255m▄\x1b[38;2;21;21;21;48;2;255;255;255m▄\x1b[38;2;25;25;25;48;2;255;255;255m▄\x1b[38;2;11;11;11;48;2;255;255;255m▄\x1b[38;2;3;3;3;48;2;255;255;255m▄\x1b[38;2;1;1;1;48;2;255;255;255m▄\x1b[38;2;0;0;0;48;2;253;253;253m▄\x1b[38;2;1;1;1;48;2;109;109;109m▄\x1b[38;2;2;2;2;48;2;0;0;0m▄\x1b[48;2;2;2;2m   \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;253;253;253m \x1b[48;2;255;255;255m  \x1b[48;2;5;5;5m \x1b[48;2;2;2;2m     \x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;4;4;4m \x1b[48;2;2;2;2m \x1b[38;2;0;0;0;48;2;4;4;4m▄\x1b[38;2;14;14;14;48;2;248;248;248m▄\x1b[48;2;255;255;255m  \x1b[38;2;255;255;255;48;2;251;251;251m▄\x1b[38;2;255;255;255;48;2;3;3;3m▄\x1b[38;2;6;6;6;48;2;8;8;8m▄\x1b[38;2;3;3;3;48;2;2;2;2m▄▄\x1b[38;2;8;8;8;48;2;2;2;2m▄\x1b[38;2;5;5;5;48;2;2;2;2m▄\x1b[38;2;79;79;79;48;2;10;10;10m▄\x1b[38;2;0;0;0;48;2;2;2;2m▄\x1b[48;2;2;2;2m   \x1b[48;2;246;246;246m \x1b[48;2;255;255;255m  \x1b[48;2;253;253;253m \x1b[48;2;2;2;2m           \x1b[m\n" +
		"\x1b[48;2;2;2;2m   \x1b[48;2;253;253;253m \x1b[48;2;255;255;255m  \x1b[48;2;5;5;5m \x1b[48;2;2;2;2m     \x1b[48;2;0;0;0m \x1b[48;2;255;255;255m   \x1b[48;2;4;4;4m \x1b[48;2;2;2;2m \x1b[38;2;2;2;2;48;2;0;0;0m▄▄\x1b[38;2;1;1;1;48;2;231;231;231m▄\x1b[38;2;151;151;151;48;2;255;255;255m▄\x1b[48;2;255;255;255m \x1b[38;2;255;255;255;48;2;250;250;250m▄\x1b[38;2;255;255;255;48;2;253;253;253m▄\x1b[38;2;255;255;255;48;2;251;251;251m▄\x1b[38;2;255;255;255;48;2;222;222;222m▄\x1b[38;2;255;255;255;48;2;251;251;251m▄\x1b[38;2;255;255;255;48;2;252;252;252m▄\x1b[38;2;255;255;255;48;2;248;248;248m▄\x1b[48;2;0;0;0m \x1b[48;2;2;2;2m   \x1b[48;2;246;246;246m \x1b[48;2;255;255;255m  \x1b[48;2;253;253;253m \x1b[48;2;2;2;2m           \x1b[m\n" +
		"\x1b[38;2;11;0;6;48;2;0;7;0m▄\x1b[38;2;132;30;51;48;2;7;0;5m▄\x1b[38;2;145;26;42;48;2;0;8;7m▄\x1b[38;2;142;26;45;48;2;102;106;107m▄\x1b[38;2;142;26;45;48;2;91;95;96m▄\x1b[38;2;142;26;45;48;2;99;103;104m▄\x1b[38;2;142;26;45;48;2;1;3;4m▄\x1b[38;2;142;26;45;48;2;0;3;4m▄▄\x1b[38;2;142;26;45;48;2;0;2;4m▄▄▄\x1b[38;2;142;26;45;48;2;0;0;2m▄\x1b[38;2;142;26;45;48;2;92;95;96m▄\x1b[38;2;142;26;45;48;2;91;95;96m▄▄\x1b[38;2;142;26;45;48;2;0;1;2m▄\x1b[38;2;142;26;45;48;2;0;3;4m▄▄▄▄▄\x1b[38;2;142;26;45;48;2;4;8;9m▄\x1b[38;2;142;26;45;48;2;54;58;59m▄\x1b[38;2;142;26;45;48;2;239;242;243m▄\x1b[38;2;142;26;45;48;2;250;253;254m▄\x1b[38;2;142;26;45;48;2;252;254;255m▄\x1b[38;2;142;26;45;48;2;250;253;253m▄\x1b[38;2;142;26;45;48;2;178;181;182m▄\x1b[38;2;142;26;45;48;2;23;25;27m▄\x1b[38;2;142;26;45;48;2;0;1;2m▄\x1b[38;2;142;26;45;48;2;0;2;4m▄▄\x1b[38;2;142;26;45;48;2;0;3;4m▄\x1b[38;2;142;26;45;48;2;77;81;82m▄\x1b[38;2;142;26;45;48;2;91;95;96m▄▄\x1b[38;2;142;26;45;48;2;99;104;104m▄\x1b[38;2;142;26;45;48;2;0;3;4m▄▄▄\x1b[38;2;142;26;45;48;2;0;2;4m▄▄▄▄▄▄\x1b[38;2;116;23;38;48;2;4;3;0m▄\x1b[38;2;0;8;0;48;2;0;4;0m▄\x1b[m\n" +
		"\x1b[38;2;0;5;5;48;2;0;9;8m▄\x1b[38;2;160;19;48;48;2;142;30;46m▄\x1b[38;2;197;2;35;48;2;179;15;29m▄\x1b[38;2;184;10;37;48;2;189;8;34m▄\x1b[38;2;184;10;37;48;2;189;8;33m▄\x1b[38;2;184;10;37;48;2;189;8;34m▄▄\x1b[38;2;184;9;37;48;2;189;8;34m▄\x1b[38;2;184;9;37;48;2;190;8;34m▄\x1b[38;2;184;9;37;48;2;190;8;35m▄\x1b[38;2;184;9;38;48;2;190;8;35m▄\x1b[38;2;184;9;38;48;2;190;7;35m▄\x1b[38;2;184;9;38;48;2;191;7;35m▄\x1b[38;2;184;9;38;48;2;190;7;35m▄\x1b[38;2;184;9;38;48;2;190;8;35m▄\x1b[38;2;184;9;37;48;2;190;8;35m▄\x1b[38;2;184;9;37;48;2;190;8;34m▄\x1b[38;2;184;9;37;48;2;189;8;34m▄\x1b[38;2;184;10;37;48;2;189;8;34m▄▄\x1b[38;2;184;10;37;48;2;189;8;33m▄\x1b[38;2;184;10;37;48;2;189;8;34m▄▄\x1b[38;2;184;9;37;48;2;189;8;34m▄\x1b[38;2;184;9;37;48;2;190;8;34m▄▄\x1b[38;2;184;9;38;48;2;190;8;35m▄▄\x1b[38;2;184;9;38;48;2;191;7;35m▄▄\x1b[38;2;184;9;38;48;2;190;8;35m▄▄\x1b[38;2;184;9;37;48;2;190;8;34m▄▄\x1b[38;2;184;9;37;48;2;189;8;34m▄\x1b[38;2;184;10;37;48;2;189;8;34m▄\x1b[38;2;184;10;37;48;2;189;8;33m▄▄\x1b[38;2;184;10;37;48;2;189;8;34m▄\x1b[38;2;184;9;37;48;2;189;8;34m▄\x1b[38;2;184;9;37;48;2;190;8;34m▄▄\x1b[38;2;184;9;38;48;2;190;8;35m▄▄\x1b[38;2;184;9;38;48;2;191;7;35m▄▄\x1b[38;2;184;9;38;48;2;190;8;35m▄\x1b[38;2;165;20;47;48;2;175;27;59m▄\x1b[38;2;1;0;10;48;2;0;7;1m▄\x1b[m\n" +
		"\x1b[38;2;2;2;2;48;2;1;2;5m▄\x1b[38;2;2;2;2;48;2;140;28;47m▄\x1b[38;2;2;2;2;48;2;166;17;36m▄\x1b[38;2;2;2;2;48;2;177;9;45m▄▄▄▄▄▄\x1b[38;2;2;2;2;48;2;177;9;46m▄▄▄▄▄▄▄\x1b[38;2;2;2;2;48;2;177;9;45m▄▄▄▄▄▄▄▄▄▄\x1b[38;2;2;2;2;48;2;177;9;46m▄▄▄▄▄▄\x1b[38;2;2;2;2;48;2;177;9;45m▄▄▄▄▄▄▄▄▄▄\x1b[38;2;2;2;2;48;2;177;9;46m▄▄▄▄▄\x1b[38;2;2;2;2;48;2;133;30;43m▄\x1b[38;2;2;2;2;48;2;0;2;10m▄\x1b[m\n"
}
