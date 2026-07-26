package releasepkg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type signOptions struct {
	Mode              SignMode
	GPGKeyID          string
	GPGHome           string
	PinnedFingerprint string
	NotationName      string
	NotationValue     string
}

func maybeSign(ctx context.Context, opts signOptions, artifact, signature string) (bool, error) {
	if opts.Mode == SignOff {
		return false, nil
	}
	notation := ""
	if (opts.NotationName == "") != (opts.NotationValue == "") {
		return false, errors.New("signature notation name and value must be set together")
	}
	if opts.NotationName != "" {
		if strings.ContainsAny(opts.NotationName, "!=\r\n") || strings.ContainsAny(opts.NotationValue, "\r\n") {
			return false, errors.New("signature notation contains invalid characters")
		}
		// The version binding is critical: generic OpenPGP verification must fail
		// unless the verifier explicitly recognizes and checks this notation.
		notation = "!" + opts.NotationName + "=" + opts.NotationValue
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		if opts.Mode == SignRequired {
			return false, errors.New("a signature is required but gpg is unavailable")
		}
		return false, nil
	}
	home := opts.GPGHome
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			if opts.Mode == SignRequired {
				return false, fmt.Errorf("resolve GPG home: %w", err)
			}
			return false, nil
		}
		home = filepath.Join(userHome, ".gnupg")
	}
	keyID := opts.GPGKeyID
	if keyID == "" {
		keyID = opts.PinnedFingerprint
	}

	fingerprint, listErr := secretKeyFingerprint(ctx, gpg, home, keyID)
	if listErr != nil || !strings.EqualFold(fingerprint, opts.PinnedFingerprint) {
		if opts.Mode == SignRequired {
			if listErr != nil {
				return false, fmt.Errorf("pinned release signing key is unavailable: %w", listErr)
			}
			return false, fmt.Errorf("release signing key fingerprint %q does not match pinned %q", fingerprint, opts.PinnedFingerprint)
		}
		return false, nil
	}

	signArgs := []string{"--yes", "--armor", "--detach-sign", "--local-user", keyID}
	if notation != "" {
		signArgs = append(signArgs, "--sig-notation", notation)
	}
	signArgs = append(signArgs, "-o", signature, "--", artifact)
	if err := runGPG(ctx, gpg, home, signArgs...); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("sign release artifact: %w", err)
	}
	if err := os.Chmod(signature, 0o644); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("normalize signature mode: %w", err)
	}
	verifyArgs := []string{"--status-fd=1"}
	if opts.NotationName != "" {
		verifyArgs = append(verifyArgs, "--known-notation", opts.NotationName, "--show-notation")
	}
	verifyArgs = append(verifyArgs, "--verify", signature, artifact)
	status, err := runGPGOutput(ctx, gpg, home, verifyArgs...)
	if err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("verify generated release artifact signature: %w", err)
	}
	if !validSignatureFingerprint(status, opts.PinnedFingerprint) {
		_ = os.Remove(signature)
		return false, fmt.Errorf("generated signature is not bound to pinned fingerprint %s", opts.PinnedFingerprint)
	}
	if opts.NotationName != "" && !validSignatureNotation(status, opts.NotationName, opts.NotationValue) {
		_ = os.Remove(signature)
		return false, fmt.Errorf("generated signature is not bound to notation %s=%s", opts.NotationName, opts.NotationValue)
	}
	return true, nil
}

func secretKeyFingerprint(ctx context.Context, gpg, home, keyID string) (string, error) {
	out, err := runGPGOutput(ctx, gpg, home, "--with-colons", "--list-secret-keys", "--", keyID)
	if err != nil {
		return "", err
	}
	sawPrimary := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "sec" {
			sawPrimary = true
			continue
		}
		if sawPrimary && fields[0] == "fpr" && len(fields) > 9 {
			return strings.ToUpper(fields[9]), nil
		}
	}
	return "", errors.New("GPG did not return a primary secret-key fingerprint")
}

func validSignatureFingerprint(status []byte, pinned string) bool {
	validCount, pinnedCount := 0, 0
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "[GNUPG:]" || fields[1] != "VALIDSIG" {
			continue
		}
		validCount++
		if strings.EqualFold(fields[2], pinned) || strings.EqualFold(fields[len(fields)-1], pinned) {
			pinnedCount++
		}
	}
	return validCount == 1 && pinnedCount == 1
}

func validSignatureNotation(status []byte, name, value string) bool {
	nameCount, nameMatches := 0, 0
	flagsCount, flagsMatches := 0, 0
	dataCount, dataMatches := 0, 0
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "NOTATION_NAME":
			nameCount++
			if len(fields) == 3 && fields[2] == name {
				nameMatches++
			}
		case "NOTATION_FLAGS":
			flagsCount++
			if len(fields) == 4 && fields[2] == "1" && fields[3] == "1" {
				flagsMatches++
			}
		case "NOTATION_DATA":
			dataCount++
			if len(fields) == 3 && fields[2] == value {
				dataMatches++
			}
		}
	}
	return nameCount == 1 && nameMatches == 1 &&
		flagsCount == 1 && flagsMatches == 1 &&
		dataCount == 1 && dataMatches == 1
}

func runGPG(ctx context.Context, gpg, home string, args ...string) error {
	_, err := runGPGOutput(ctx, gpg, home, args...)
	return err
}

func runGPGOutput(ctx context.Context, gpg, home string, args ...string) ([]byte, error) {
	timed, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	base := []string{"--batch", "--no-tty", "--homedir", home}
	return runCombined(timed, "", nil, gpg, append(base, args...)...)
}
