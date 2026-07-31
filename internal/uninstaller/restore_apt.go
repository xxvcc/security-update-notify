package uninstaller

import (
	"bytes"

	"errors"
	"fmt"

	"path/filepath"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"

	"github.com/xxvcc/security-update-notify/internal/dependencyproof"
)

func restoreAPT(root string) (string, error) {
	return restoreAPTWithRemove(root, nil)
}

func restoreAPTWithRemove(root string, beforeRemove func(string) error) (string, error) {
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		return "", fmt.Errorf("open apt configuration directory: %w", err)
	}
	if directory == nil {
		return "", nil
	}
	defer directory.close()
	names, err := directory.names()
	if err != nil {
		return "", fmt.Errorf("list apt backups: %w", err)
	}
	if artifact := unfinishedRestoreArtifact(names); artifact != "" {
		return "", fmt.Errorf("unfinished apt restore transaction requires manual recovery: %s", directory.host(artifact))
	}
	destination := filepath.Base(aptPeriodicLogical)
	fixed := filepath.Base(aptStableLogical)
	marker := filepath.Base(aptAbsentLogical)
	legacyMarker := filepath.Base(aptLegacyAbsent)
	proof := filepath.Base(aptDependencyProof)
	timestamps := append(
		restoreTimestampNames(names, fixed+".", ""),
		restoreTimestampNames(names, destination+".security-update-notify.", ".bak")...,
	)
	timestampSnapshots, err := directory.readSnapshots(timestamps, restoreConfigLimit)
	if err != nil {
		return "", fmt.Errorf("inspect apt timestamp backups: %w", err)
	}

	fixedSnapshot, err := directory.readRegular(fixed, restoreConfigLimit)
	if err != nil {
		return "", fmt.Errorf("inspect apt fixed backup: %w", err)
	}
	markerSnapshot, err := readAPTMarkerSnapshot(directory, marker)
	if err != nil {
		return "", fmt.Errorf("inspect apt absence marker: %w", err)
	}
	legacyMarkerSnapshot, err := readAPTMarkerSnapshot(directory, legacyMarker)
	if err != nil {
		return "", fmt.Errorf("inspect legacy apt absence marker: %w", err)
	}
	proofSnapshot, err := directory.readRegular(proof, 256)
	if err != nil {
		return "", fmt.Errorf("inspect apt dependency proof: %w", err)
	}

	source := ""
	if fixedSnapshot.exists {
		source = fixed
	}
	markerExists := markerSnapshot.exists || legacyMarkerSnapshot.exists
	preserveDependencyDefault := false
	var configSnapshot regularSnapshot
	if source != "" || markerExists {
		configSnapshot, err = directory.readRegular(destination, restoreConfigLimit)
		if err != nil {
			return "", fmt.Errorf("inspect apt configuration: %w", err)
		}
	}
	if source == "" && markerExists {
		managedHistory := aptBackupsContainOnlyManagedPolicyAt(timestampSnapshots, timestamps)
		if proofSnapshot.exists {
			if !configSnapshot.exists {
				return "", errors.New("inspect apt dependency proof: 20auto-upgrades is missing")
			}
			if !bytes.Equal(proofSnapshot.data, dependencyproof.Contents("apt", configSnapshot.data)) {
				return "", errors.New("inspect apt dependency proof: proof does not match 20auto-upgrades")
			}
			preserveDependencyDefault = true
		} else if !managedHistory || (configSnapshot.exists && !bytes.Equal(configSnapshot.data, []byte(aptconfig.Periodic))) {
			return "", errors.New("inspect apt dependency proof: cannot prove that 20auto-upgrades is a SUN-managed file or retained dependency default")
		}
	}

	var committedConfig *regularSnapshot
	if source != "" {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", fmt.Errorf("restore apt configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		restored, err := directory.restoreFile(source, destination, fixedSnapshot, configSnapshot)
		if err != nil {
			return "", fmt.Errorf("restore apt configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		committedConfig = &restored
	} else if markerExists && preserveDependencyDefault {
		committedConfig = &configSnapshot
	} else if markerExists && configSnapshot.exists {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", fmt.Errorf("restore absent apt configuration: %w", err)
		}
		if err := directory.removeValidated(destination, configSnapshot); err != nil {
			return "", fmt.Errorf("restore absent apt configuration: %w", err)
		}
	}

	if markerExists {
		for _, candidate := range []struct {
			name     string
			snapshot regularSnapshot
		}{{marker, markerSnapshot}, {legacyMarker, legacyMarkerSnapshot}} {
			if candidate.snapshot.exists {
				if err := callRestoreRemoveHook(beforeRemove, directory.host(candidate.name)); err != nil {
					return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w", err)
				}
			}
		}
		if committedConfig != nil {
			if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w",
					directory.recordConflict("apt configuration changed before marker commit", err))
			}
		}
		if proofSnapshot.exists {
			if err := directory.revalidate(proof, proofSnapshot, 256); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w",
					directory.recordConflict("apt dependency proof changed before marker commit", err))
			}
		}
		if markerSnapshot.exists {
			if err := directory.removeValidated(marker, markerSnapshot); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w", err)
			}
		}
		if legacyMarkerSnapshot.exists {
			if err := directory.removeValidated(legacyMarker, legacyMarkerSnapshot); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w", err)
			}
		}
		if err := directory.sync(); err != nil {
			return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w",
				directory.recordConflict("sync apt marker commit", err))
		}
	}
	if committedConfig != nil {
		if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
			return sourcePath(directory, source), fmt.Errorf("validate restored apt configuration before cleanup: %w",
				directory.recordConflict("apt configuration changed before cleanup", err))
		}
	}
	metadata := append(append([]string(nil), timestamps...), fixed)
	cleanupSnapshots := make(map[string]regularSnapshot, len(timestampSnapshots)+2)
	for name, snapshot := range timestampSnapshots {
		cleanupSnapshots[name] = snapshot
	}
	cleanupSnapshots[fixed] = fixedSnapshot
	cleanupSnapshots[proof] = proofSnapshot
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, metadata...); err != nil {
		return sourcePath(directory, source), fmt.Errorf("clean apt backups: %w", err)
	}
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, proof); err != nil {
		return sourcePath(directory, source), fmt.Errorf("clean apt dependency proof: %w", err)
	}
	if err := directory.sync(); err != nil {
		return sourcePath(directory, source), fmt.Errorf("sync apt backup cleanup: %w",
			directory.recordConflict("sync apt backup cleanup", err))
	}
	return sourcePath(directory, source), nil
}

func readAPTMarkerSnapshot(directory *restoreDirectory, name string) (regularSnapshot, error) {
	snapshot, err := directory.readRegular(name, 256)
	if err != nil || !snapshot.exists {
		return snapshot, err
	}
	if string(snapshot.data) != aptAbsentContents {
		return regularSnapshot{}, errors.New("absence marker has invalid contents")
	}
	return snapshot, nil
}

func aptBackupsContainOnlyManagedPolicyAt(snapshots map[string]regularSnapshot, names []string) bool {
	for _, candidate := range names {
		snapshot := snapshots[candidate]
		if !bytes.Equal(snapshot.data, []byte(aptconfig.Periodic)) {
			return false
		}
	}
	return true
}

func sourcePath(directory *restoreDirectory, name string) string {
	if name == "" {
		return ""
	}
	return directory.host(name)
}

func callRestoreRemoveHook(hook func(string) error, path string) error {
	if hook == nil {
		return nil
	}
	return hook(path)
}

func removeRestoreSnapshots(directory *restoreDirectory, hook func(string) error, snapshots map[string]regularSnapshot, names ...string) error {
	for _, name := range names {
		snapshot := snapshots[name]
		if !snapshot.exists {
			continue
		}
		if err := callRestoreRemoveHook(hook, directory.host(name)); err != nil {
			return err
		}
		if err := directory.removeValidated(name, snapshot); err != nil {
			return err
		}
	}
	return nil
}
