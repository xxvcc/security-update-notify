package installer

import (
	"bytes"

	"errors"

	"io/fs"

	"path"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/dependencyproof"
)

// migrateAPTMetadata moves older SUN metadata to names ending in .bak. APT
// silently ignores that suffix; the former .absent and .bak.<timestamp> names
// produced a notice during every apt invocation.
func (i *Installer) migrateAPTMetadata(b *backup) error {
	if err := i.ensureDir(path.Dir(aptPeriodicPath), 0o755); err != nil {
		return failure("create apt configuration directory", err)
	}
	legacyMarker, err := i.validAPTAbsentMarkerAt(aptLegacyAbsentPath)
	if err != nil {
		return failure("inspect legacy apt absence marker", err)
	}
	if legacyMarker {
		currentMarker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
		if err != nil {
			return failure("inspect apt absence marker", err)
		}
		if !currentMarker {
			if err := i.fs.WriteFileAtomic(aptAbsentMarkerPath, []byte(aptAbsentMarkerContents), 0o600); err != nil {
				return failure("migrate apt absence marker", err)
			}
			// This is a transaction-owned rename, not a package-created default.
			// Restoring it together with the legacy marker would leave both names.
			b.skipDependencyCapturePath[aptAbsentMarkerPath] = true
		}
		if err := i.fs.Remove(aptLegacyAbsentPath); err != nil {
			return failure("remove legacy apt absence marker", err)
		}
	}

	entries, err := i.fs.ReadDir(path.Dir(aptPeriodicPath))
	if err != nil {
		return failure("list apt configuration backups", err)
	}
	legacyPrefix := path.Base(aptStableBackupPath) + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, legacyPrefix) || len(name) == len(legacyPrefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, legacyPrefix)
		if !validBackupTimestamp(suffix) {
			continue
		}
		source := path.Join(path.Dir(aptPeriodicPath), name)
		destination := aptPeriodicPath + ".security-update-notify." + suffix + ".bak"
		if err := i.snapshotAdditionalPath(b, source); err != nil {
			return err
		}
		if err := i.snapshotAdditionalPath(b, destination); err != nil {
			return err
		}
		sourceExists, err := i.validBaselineFile(source)
		if err != nil || !sourceExists {
			if err == nil {
				err = errors.New("legacy apt backup disappeared")
			}
			return failure("inspect legacy apt backup", err)
		}
		destinationExists, err := i.validBaselineFile(destination)
		if err != nil {
			return failure("inspect migrated apt backup", err)
		}
		if destinationExists {
			sourceData, sourceStillExists, sourceErr := i.readTrustedRegularFile(source, 4<<20)
			destinationData, destinationStillExists, destinationErr := i.readTrustedRegularFile(destination, 4<<20)
			if sourceErr != nil || destinationErr != nil || !sourceStillExists || !destinationStillExists || !bytes.Equal(sourceData, destinationData) {
				return failure("migrate apt backup", errors.New("legacy and migrated backups differ: "+name))
			}
		} else if err := i.copyNode(source, destination); err != nil {
			return failure("migrate apt backup", err)
		}
		if err := i.fs.Remove(source); err != nil {
			return failure("remove legacy apt backup", err)
		}
	}
	return nil
}

func (i *Installer) recordAPTAbsentBaseline() error {
	if err := i.ensureDir(path.Dir(aptAbsentMarkerPath), 0o755); err != nil {
		return failure("create apt configuration directory", err)
	}
	stable, err := i.validBaselineFile(aptStableBackupPath)
	if err != nil {
		return failure("inspect stable apt backup", err)
	}
	marker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
	if err != nil {
		return failure("inspect apt absence marker", err)
	}
	if stable || marker {
		return nil
	}
	if err := i.fs.WriteFileAtomic(aptAbsentMarkerPath, []byte(aptAbsentMarkerContents), 0o600); err != nil {
		return failure("record absent apt periodic config", err)
	}
	return nil
}

func (i *Installer) validAPTAbsentMarkerAt(markerPath string) (bool, error) {
	return i.validAbsentMarkerAt(markerPath, aptAbsentMarkerContents, "apt")
}

// recordAPTDependencyProof binds a newly retained unattended-upgrades default
// to the package transaction that created it. A retry or immediate purge can
// then preserve the exact bytes without guessing from the file's presence.
func (i *Installer) recordAPTDependencyProof() error {
	data, exists, err := i.readTrustedRegularFile(aptPeriodicPath, 4<<20)
	if err != nil {
		return failure("inspect partial apt dependency config", err)
	}
	if !exists {
		return nil
	}
	matched, err := i.validAPTDependencyProof(data)
	if err != nil {
		return failure("inspect apt dependency proof", err)
	}
	if matched {
		return nil
	}
	if err := i.fs.WriteFileAtomic(aptDependencyProofPath, aptDependencyProofContents(data), 0o600); err != nil {
		return failure("record apt dependency proof", err)
	}
	return nil
}

func aptDependencyProofContents(data []byte) []byte {
	return dependencyproof.Contents("apt", data)
}

func (i *Installer) validAPTDependencyProof(config []byte) (bool, error) {
	proof, exists, err := i.readTrustedRegularFile(aptDependencyProofPath, 256)
	if err != nil || !exists {
		return exists, err
	}
	if !bytes.Equal(proof, aptDependencyProofContents(config)) {
		return false, errors.New("apt dependency proof does not match 20auto-upgrades")
	}
	return true, nil
}

// persistAPTDependencyBaseline keeps the vendor periodic configuration created
// by the retained unattended-upgrades package. Current-file promotion requires
// either this transaction's provenance or a proof matching the exact content;
// older SUN installs can recover from their earliest non-SUN timestamp.
func (i *Installer) persistAPTDependencyBaseline(b *backup, configOriginallyAbsent, packageInstallAttempted bool) error {
	marker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
	if err != nil {
		return failure("inspect apt absence marker after dependencies", err)
	}
	if !marker {
		return nil
	}
	configExists, err := i.validBaselineFile(aptPeriodicPath)
	if err != nil {
		return failure("inspect dependency-created apt periodic config", err)
	}
	stable, err := i.validBaselineFile(aptStableBackupPath)
	if err != nil {
		return failure("inspect stable apt backup after dependencies", err)
	}
	if !stable {
		baseline, err := i.oldestAPTProjectBackup(true)
		if err != nil {
			return failure("select original apt backup after dependencies", err)
		}
		if baseline == "" {
			if !configExists {
				proofExists, proofErr := i.validBaselineFile(aptDependencyProofPath)
				if proofErr != nil {
					return failure("inspect apt dependency proof", proofErr)
				}
				if proofExists {
					return failure("persist apt vendor baseline", errors.New("20auto-upgrades is missing but its dependency proof remains"))
				}
				return nil
			}
			data, currentExists, err := i.readTrustedRegularFile(aptPeriodicPath, 4<<20)
			if err != nil || !currentExists {
				if err == nil {
					err = fs.ErrNotExist
				}
				return failure("read apt vendor baseline", err)
			}
			if !configOriginallyAbsent || !packageInstallAttempted {
				// A marker plus the exact SUN policy and no timestamp history is the
				// normal state when the package was already installed but this file was
				// absent. Keep the absence baseline for purge.
				if bytes.Equal(data, []byte(aptPeriodicConfig)) {
					return nil
				}
				proven, err := i.validAPTDependencyProof(data)
				if err != nil {
					return failure("validate apt dependency proof", err)
				}
				if !proven {
					return failure("persist apt vendor baseline", errors.New(
						"cannot prove that 20auto-upgrades is a retained dependency default; restore a trusted vendor baseline before retrying"))
				}
			}
			baseline = aptPeriodicPath
		}
		if err := i.copyNode(baseline, aptStableBackupPath); err != nil {
			return failure("persist apt vendor baseline", err)
		}
		if err := i.captureDependencyDefaults(b); err != nil {
			return err
		}
	}
	for _, metadata := range []struct {
		path string
		op   string
	}{
		{path: aptAbsentMarkerPath, op: "replace apt absence marker with vendor baseline"},
		{path: aptLegacyAbsentPath, op: "remove superseded legacy apt absence marker"},
		{path: aptDependencyProofPath, op: "remove promoted apt dependency proof"},
	} {
		// Publish the adopted absence before unlinking the live metadata. A crash
		// in between then makes recovery finish the unlink instead of resurrecting
		// a marker alongside the promoted stable baseline.
		if err := i.keepPathAbsentOnRollback(b, metadata.path); err != nil {
			return err
		}
		if err := i.fs.Remove(metadata.path); err != nil {
			return failure(metadata.op, err)
		}
	}
	return nil
}
