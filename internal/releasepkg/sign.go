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

	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

type signOptions struct {
	Mode              SignMode
	GPGKeyID          string
	GPGHome           string
	PinnedFingerprint string
	TrustedPublicKey  []byte
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
	verificationHome, cleanupVerification, err := trustedVerificationHome(
		ctx, gpg, opts.TrustedPublicKey, opts.PinnedFingerprint,
	)
	if err != nil {
		return false, fmt.Errorf("prepare published release verification key: %w", err)
	}
	defer cleanupVerification()
	artifactState, err := captureRegularFileState(artifact, maxUncompressedSize)
	if err != nil {
		return false, fmt.Errorf("capture release artifact before signing: %w", err)
	}
	artifactFile, artifactInfo, err := openBoundedRegular(artifact, maxUncompressedSize, true)
	if err != nil {
		return false, fmt.Errorf("open release artifact for signing: %w", err)
	}
	defer artifactFile.Close()
	if !os.SameFile(artifactState.info, artifactInfo) || !sameRegularMetadata(artifactState.info, artifactInfo) {
		return false, errors.New("release artifact changed before signing")
	}

	signArgs := []string{"--armor", "--detach-sign", "--local-user", keyID}
	if notation != "" {
		signArgs = append(signArgs, "--sig-notation", notation)
	}
	if _, err := artifactFile.Seek(0, 0); err != nil {
		return false, fmt.Errorf("rewind release artifact for signing: %w", err)
	}
	signArgs = append(signArgs, "--output", "-", "--", inheritedReleaseFilePath(0))
	signatureBytes, err := runGPGCaptureStdout(ctx, gpg, home, []*os.File{artifactFile}, signArgs...)
	if err != nil {
		return false, fmt.Errorf("sign release artifact: %w", err)
	}
	if len(signatureBytes) == 0 || int64(len(signatureBytes)) > maxReleaseSignatureBytes {
		return false, fmt.Errorf("generated signature is empty or exceeds %d bytes", maxReleaseSignatureBytes)
	}
	if err := writeExclusiveRegular(signature, signatureBytes, 0o644); err != nil {
		return false, fmt.Errorf("write generated signature: %w", err)
	}
	if err := verifyRegularFileState(artifact, artifactState, maxUncompressedSize); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("release artifact changed while signing: %w", err)
	}
	signatureState, err := captureRegularFileState(signature, maxReleaseSignatureBytes)
	if err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("capture generated signature: %w", err)
	}
	signatureFile, signatureInfo, err := openBoundedRegular(signature, maxReleaseSignatureBytes, true)
	if err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("open generated signature: %w", err)
	}
	defer signatureFile.Close()
	if !os.SameFile(signatureState.info, signatureInfo) || !sameRegularMetadata(signatureState.info, signatureInfo) {
		_ = os.Remove(signature)
		return false, errors.New("generated signature changed before verification")
	}
	verifyArgs := []string{"--status-fd=1"}
	if opts.NotationName != "" {
		verifyArgs = append(verifyArgs, "--known-notation", opts.NotationName, "--show-notation")
	}
	if _, err := artifactFile.Seek(0, 0); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("rewind release artifact for verification: %w", err)
	}
	if _, err := signatureFile.Seek(0, 0); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("rewind generated signature: %w", err)
	}
	verifyArgs = append(verifyArgs, "--verify", inheritedReleaseFilePath(0), inheritedReleaseFilePath(1))
	status, err := runGPGOutputFiles(ctx, gpg, verificationHome, []*os.File{signatureFile, artifactFile}, verifyArgs...)
	if err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("verify generated signature with published release key: %w", err)
	}
	if !validSignatureFingerprint(status, opts.PinnedFingerprint) {
		_ = os.Remove(signature)
		return false, fmt.Errorf("generated signature is not bound to pinned fingerprint %s", opts.PinnedFingerprint)
	}
	if opts.NotationName != "" && !validSignatureNotation(status, opts.NotationName, opts.NotationValue) {
		_ = os.Remove(signature)
		return false, fmt.Errorf("generated signature is not bound to notation %s=%s", opts.NotationName, opts.NotationValue)
	}
	if err := verifyRegularFileState(artifact, artifactState, maxUncompressedSize); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("release artifact changed during signature verification: %w", err)
	}
	if err := verifyRegularFileState(signature, signatureState, maxReleaseSignatureBytes); err != nil {
		_ = os.Remove(signature)
		return false, fmt.Errorf("generated signature changed during verification: %w", err)
	}
	return true, nil
}

func trustedVerificationHome(ctx context.Context, gpg string, publicKey []byte, pinned string) (string, func(), error) {
	if len(publicKey) == 0 {
		return "", func() {}, errors.New("published release verification key is required")
	}
	home, err := os.MkdirTemp("", "sun-release-published-key-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(home) }
	if err := os.Chmod(home, 0o700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	keyPath := filepath.Join(home, "release-signing.pub.asc")
	if err := os.WriteFile(keyPath, publicKey, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := runGPG(ctx, gpg, home, "--import", "--", keyPath); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("import published release key: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(ctx, gpg, home)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if !strings.EqualFold(fingerprint, pinned) {
		cleanup()
		return "", func() {}, fmt.Errorf("published release key fingerprint %q does not match pinned %q", fingerprint, pinned)
	}
	return home, cleanup, nil
}

func publicKeyFingerprint(ctx context.Context, gpg, home string) (string, error) {
	out, err := runGPGOutput(ctx, gpg, home, "--with-colons", "--list-keys")
	if err != nil {
		return "", err
	}
	primaryCount := 0
	primaryFingerprint := ""
	wantFingerprint := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "pub":
			primaryCount++
			wantFingerprint = true
		case "fpr":
			if wantFingerprint && len(fields) > 9 {
				primaryFingerprint = strings.ToUpper(fields[9])
				wantFingerprint = false
			}
		case "sub":
			wantFingerprint = false
		}
	}
	if primaryCount != 1 {
		return "", fmt.Errorf("published release keyring must contain exactly one primary key, got %d", primaryCount)
	}
	if primaryFingerprint == "" {
		return "", errors.New("published release keyring has no primary fingerprint")
	}
	return primaryFingerprint, nil
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
	goodCount, outcomeCount := 0, 0
	validCount, pinnedCount := 0, 0
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "GOODSIG":
			outcomeCount++
			goodCount++
		case "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG":
			// VALIDSIG alone does not reject an expired or revoked signing key.
			// Require GPG's sole high-level outcome to be GOODSIG as well.
			outcomeCount++
		case "VALIDSIG":
			if len(fields) < 3 {
				continue
			}
			validCount++
			if strings.EqualFold(fields[2], pinned) || strings.EqualFold(fields[len(fields)-1], pinned) {
				pinnedCount++
			}
		}
	}
	return outcomeCount == 1 && goodCount == 1 && validCount == 1 && pinnedCount == 1
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
	return runGPGOutputFiles(ctx, gpg, home, nil, args...)
}

func runGPGOutputFiles(ctx context.Context, gpg, home string, files []*os.File, args ...string) ([]byte, error) {
	return runGPGCaptureStdout(ctx, gpg, home, files, args...)
}

func runGPGCaptureStdout(ctx context.Context, gpg, home string, files []*os.File, args ...string) ([]byte, error) {
	timed, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	base := []string{"--no-options", "--batch", "--no-tty", "--homedir", home}
	cmd := sysexec.CommandContext(timed, gpg, append(base, args...)...)
	cmd.ExtraFiles = append([]*os.File(nil), files...)
	var stdout, stderr cappedCombinedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if stdout.truncated || stderr.truncated {
		return nil, fmt.Errorf("gpg output exceeds %d bytes", maxCombinedCommandOutput)
	}
	if timed.Err() != nil {
		return nil, fmt.Errorf("gpg timed out")
	}
	if err != nil {
		message := commandErrorSummary(stderr.buf.Bytes())
		if message != "" {
			return nil, fmt.Errorf("gpg: %w: %s", err, message)
		}
		return nil, fmt.Errorf("gpg: %w", err)
	}
	return append([]byte(nil), stdout.buf.Bytes()...), nil
}

func inheritedReleaseFilePath(index int) string {
	return fmt.Sprintf("/proc/self/fd/%d", 3+index)
}
