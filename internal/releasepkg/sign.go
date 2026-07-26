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
}

func maybeSign(ctx context.Context, opts signOptions, tarball, signature string) (bool, error) {
	if opts.Mode == SignOff {
		return false, nil
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

	if err := runGPG(ctx, gpg, home,
		"--yes", "--armor", "--detach-sign", "--local-user", keyID,
		"-o", signature, "--", tarball,
	); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("sign release archive: %w", err)
	}
	if err := os.Chmod(signature, 0o644); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("normalize signature mode: %w", err)
	}
	status, err := runGPGOutput(ctx, gpg, home, "--status-fd=1", "--verify", signature, tarball)
	if err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("verify generated release signature: %w", err)
	}
	if !validSignatureFingerprint(status, opts.PinnedFingerprint) {
		_ = os.Remove(signature)
		return false, fmt.Errorf("generated signature is not bound to pinned fingerprint %s", opts.PinnedFingerprint)
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
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "[GNUPG:]" || fields[1] != "VALIDSIG" {
			continue
		}
		if strings.EqualFold(fields[2], pinned) || strings.EqualFold(fields[len(fields)-1], pinned) {
			return true
		}
	}
	return false
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
