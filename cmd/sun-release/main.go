// Command sun-release creates the reproducible five-architecture release set.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/releasepkg"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

func main() {
	sysexec.InstallSignalForwarding()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, releasepkg.Build))
}

type buildFunc func(context.Context, releasepkg.Options) (releasepkg.Result, error)

func run(args []string, stdout, stderr io.Writer, build buildFunc) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing command")
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "package":
		return runPackage(args[1:], stdout, stderr, build)
	case "help", "-h", "--help":
		if len(args) == 1 {
			printUsage(stdout)
			return 0
		}
		if len(args) == 2 && args[1] == "package" {
			printPackageUsage(stdout, nil)
			return 0
		}
		fmt.Fprintf(stderr, "unexpected help topic: %s\n", strings.Join(args[1:], " "))
		printUsage(stderr)
		return 2
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runPackage(args []string, stdout, stderr io.Writer, build buildFunc) int {
	allowDirtyDefault, err := envBool("ALLOW_DIRTY_PACKAGE")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	releaseDefault, err := envBool("RELEASE")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	flags := flag.NewFlagSet("sun-release package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printPackageUsage(stderr, flags) }
	root := flags.String("root", envDefault("SUN_RELEASE_ROOT", "."), "repository root")
	dist := flags.String("dist", envDefault("SUN_RELEASE_DIST", "dist"), "release output directory")
	version := flags.String("version", os.Getenv("VERSION"), "compatibility assertion; must match root VERSION")
	epochText := flags.String("source-date-epoch", os.Getenv("SOURCE_DATE_EPOCH"), "reproducible Unix timestamp")
	signText := flags.String("sign", envDefault("SIGN_RELEASE", "auto"), "signature mode: auto, required, or off")
	gpgKey := flags.String("gpg-key", os.Getenv("GPG_KEY_ID"), "GPG key ID (must resolve to pinned fingerprint)")
	gpgHome := flags.String("gpg-home", os.Getenv("GNUPGHOME"), "GPG home directory")
	allowDirty := flags.Bool("allow-dirty", allowDirtyDefault, "allow dirty release sources with an explicit epoch")
	release := flags.Bool("release", releaseDefault, "require official-release signing when sign=auto")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	mode, err := releasepkg.ParseSignMode(*signText)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *release && mode == releasepkg.SignAuto {
		mode = releasepkg.SignRequired
	}
	var epoch *int64
	if *epochText != "" {
		value, err := strconv.ParseInt(*epochText, 10, 64)
		if err != nil || value < 0 {
			fmt.Fprintf(stderr, "invalid source-date-epoch %q\n", *epochText)
			return 2
		}
		epoch = &value
	}
	result, err := build(context.Background(), releasepkg.Options{
		Root: *root, DistDir: *dist, Version: *version,
		SourceDateEpoch: epoch, AllowDirty: *allowDirty, Release: *release,
		Sign: mode, GPGKeyID: *gpgKey, GPGHome: *gpgHome,
		Stdout: stdout, Stderr: stderr,
	})
	if err != nil {
		fmt.Fprintf(stderr, "sun-release: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Created:\n  %s\n  %s\n", result.Tarball, result.Checksum)
	if result.Signed {
		fmt.Fprintf(stdout, "  %s\n  %s\n", result.Signature, result.BootstrapSignature)
	}
	fmt.Fprintf(stdout, "%s  %s\n", result.SHA256, filepathBase(result.Tarball))
	return 0
}

func printUsage(out io.Writer) {
	fprintln(out, `Usage:
  sun-release package [options]

Commands:
  package   Build the reproducible five-architecture release set
  help      Show this help

Run "sun-release package --help" for package options.`)
}

func printPackageUsage(out io.Writer, flags *flag.FlagSet) {
	fprintln(out, `Usage:
  sun-release package [options]

The release version is read strictly from ROOT/VERSION.`)
	if flags != nil {
		flags.SetOutput(out)
		flags.PrintDefaults()
	}
}

func fprintln(out io.Writer, text string) {
	_, _ = fmt.Fprintln(out, text)
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "", "0", "false", "no":
		return false, nil
	case "1", "true", "yes":
		return true, nil
	default:
		return false, fmt.Errorf("invalid %s (expected 0 or 1): %q", key, os.Getenv(key))
	}
}

func filepathBase(path string) string {
	if index := strings.LastIndexAny(path, `/\\`); index >= 0 {
		return path[index+1:]
	}
	return path
}
