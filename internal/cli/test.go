package cli

import (
	"fmt"
	"os"
)

// testMode owns diagnostics and explicit notification tests. A plain test runs doctor; explicit message tests
// run only after doctor succeeds and wait for the runtime lock.
func testMode(ver string, args []string) int {
	var sendOK, simulateReboot, noDedupe bool
	lang := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--send-test":
			sendOK = true
		case "--simulate-reboot":
			simulateReboot = true
		case "--no-dedupe":
			noDedupe = true
		case "--verbose":
			// Kept as a compatibility no-op. Go diagnostics never print secrets and currently do not mask IDs.
		case "--lang":
			value, ok := takeValue(args, &i)
			if !ok {
				return 2
			}
			if value != "zh" && value != "en" {
				fmt.Fprintln(os.Stderr, "Invalid --lang (expected zh or en)")
				return 2
			}
			lang = value
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "Usage: security-update-notify test [--send-test] [--simulate-reboot] [--no-dedupe] [--verbose] [--lang zh|en]")
			return 0
		default:
			fmt.Fprintf(os.Stderr, "Unknown test argument: %s\n", safeCLIText(args[i]))
			return 2
		}
	}
	if noDedupe && !sendOK && !simulateReboot {
		fmt.Fprintln(os.Stderr, "test --no-dedupe requires --send-test or --simulate-reboot")
		return 2
	}

	doctorArgs := []string{"--doctor"}
	if lang != "" {
		doctorArgs = append(doctorArgs, "--lang", lang)
	}
	if rc := runMode(ver, doctorArgs); rc != 0 {
		return rc
	}
	if !sendOK && !simulateReboot {
		return 0
	}

	common := []string{"--wait-lock", "60"}
	if noDedupe {
		common = append(common, "--no-dedupe")
	}
	if lang != "" {
		common = append(common, "--lang", lang)
	}
	if sendOK {
		if rc := runMode(ver, append([]string{"--test-ok"}, common...)); rc != 0 {
			return rc
		}
	}
	if simulateReboot {
		if rc := runMode(ver, append([]string{"--test-reboot"}, common...)); rc != 0 {
			return rc
		}
	}
	return 0
}
