package uninstaller

import (
	"bytes"

	"errors"
	"fmt"

	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
)

func restoreDNF(root string) (string, bool, error) {
	return restoreDNFWithRemove(root, nil)
}

func restoreDNFWithRemove(root string, beforeRemove func(string) error) (string, bool, error) {
	directory, err := openRestoreDirectory(root, "/etc/dnf")
	if err != nil {
		return "", false, fmt.Errorf("open dnf configuration directory: %w", err)
	}
	if directory == nil {
		return "", false, nil
	}
	defer directory.close()
	names, err := directory.names()
	if err != nil {
		return "", false, fmt.Errorf("list dnf backups: %w", err)
	}
	if artifact := unfinishedRestoreArtifact(names); artifact != "" {
		return "", false, fmt.Errorf("unfinished dnf restore transaction requires manual recovery: %s", directory.host(artifact))
	}
	destination := dnfAutomaticName
	fixed := dnfStableName
	marker := dnfAbsentName
	proof := dnfDependencyProofName
	projectBackups := restoreTimestampNames(names, fixed+".", "")
	projectSnapshots, err := directory.readSnapshots(projectBackups, restoreConfigLimit)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf timestamp backups: %w", err)
	}

	fixedSnapshot, err := directory.readRegular(fixed, restoreConfigLimit)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf fixed backup: %w", err)
	}
	markerEngine, markerSnapshot, err := readDNFMarkerSnapshot(directory, marker)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf absence marker: %w", err)
	}
	proofSnapshot, err := directory.readRegular(proof, 256)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf dependency proof: %w", err)
	}

	source := ""
	var sourceSnapshot regularSnapshot
	if fixedSnapshot.exists {
		source = fixed
		sourceSnapshot = fixedSnapshot
	}
	markerExists := markerSnapshot.exists
	if source == "" && !markerExists {
		source = oldestSnapshotName(projectBackups, projectSnapshots)
		if source != "" {
			sourceSnapshot = projectSnapshots[source]
		}
	}
	legacy := false
	if source == "" && !markerExists {
		legacyBackups := restoreNamesWithPrefix(names, "automatic.conf.bak.")
		legacySnapshots, err := directory.readSnapshots(legacyBackups, restoreConfigLimit)
		if err != nil {
			return "", false, fmt.Errorf("inspect legacy dnf backups: %w", err)
		}
		source = newestSnapshotName(legacyBackups, legacySnapshots)
		sourceSnapshot = legacySnapshots[source]
		legacy = source != ""
	}

	preserveDependencyDefault := false
	var configSnapshot regularSnapshot
	if source != "" || markerExists {
		configSnapshot, err = directory.readRegular(destination, restoreConfigLimit)
		if err != nil {
			return "", false, fmt.Errorf("inspect dnf configuration: %w", err)
		}
	}
	// A fixed backup is the authoritative pre-SUN baseline. Dependency proof is
	// only a recovery path for an originally absent configuration when no fixed
	// baseline was durably promoted before an interrupted transaction.
	if markerExists && source == "" {
		if proofSnapshot.exists {
			if markerEngine != "dnf4" {
				return "", false, errors.New("inspect dnf dependency proof: DNF5 absence marker conflicts with DNF4 dependency proof")
			}
			if !configSnapshot.exists {
				return "", false, errors.New("inspect dnf dependency proof: automatic.conf is missing")
			}
			if !bytes.Equal(proofSnapshot.data, dnfconfig.DependencyDefaultProof(configSnapshot.data)) {
				return "", false, errors.New("inspect dnf dependency proof: proof does not match automatic.conf")
			}
			preserveDependencyDefault = true
		} else if markerEngine == "dnf4" && configSnapshot.exists {
			return "", false, errors.New("inspect dnf dependency proof: cannot prove that automatic.conf is a retained DNF4 dependency default")
		}
	}

	var committedConfig *regularSnapshot
	if preserveDependencyDefault {
		source = ""
		legacy = false
		committedConfig = &configSnapshot
	} else if source != "" {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", legacy, fmt.Errorf("restore dnf configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		restored, err := directory.restoreFile(source, destination, sourceSnapshot, configSnapshot)
		if err != nil {
			return "", legacy, fmt.Errorf("restore dnf configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		committedConfig = &restored
	} else if markerExists && configSnapshot.exists {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", false, fmt.Errorf("restore absent dnf configuration: %w", err)
		}
		if err := directory.removeValidated(destination, configSnapshot); err != nil {
			return "", false, fmt.Errorf("restore absent dnf configuration: %w", err)
		}
	}

	// Legacy backups may belong to another administrator. Preserve them, as the
	// shell uninstaller does, and remove only project-owned backups.
	if markerExists {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(marker)); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w", err)
		}
		if committedConfig != nil {
			if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
				return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w",
					directory.recordConflict("dnf configuration changed before marker commit", err))
			}
		}
		if proofSnapshot.exists {
			if err := directory.revalidate(proof, proofSnapshot, 256); err != nil {
				return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w",
					directory.recordConflict("dnf dependency proof changed before marker commit", err))
			}
		}
		if err := directory.removeValidated(marker, markerSnapshot); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w", err)
		}
		if err := directory.sync(); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w",
				directory.recordConflict("sync dnf marker commit", err))
		}
	}
	if committedConfig != nil {
		if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("validate restored dnf configuration before cleanup: %w",
				directory.recordConflict("dnf configuration changed before cleanup", err))
		}
	}
	metadata := append(append([]string(nil), projectBackups...), fixed)
	cleanupSnapshots := make(map[string]regularSnapshot, len(projectSnapshots)+2)
	for name, snapshot := range projectSnapshots {
		cleanupSnapshots[name] = snapshot
	}
	cleanupSnapshots[fixed] = fixedSnapshot
	cleanupSnapshots[proof] = proofSnapshot
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, metadata...); err != nil {
		return sourcePath(directory, source), legacy, fmt.Errorf("clean dnf backups: %w", err)
	}
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, proof); err != nil {
		return sourcePath(directory, source), legacy, fmt.Errorf("clean dnf dependency proof: %w", err)
	}
	if err := directory.sync(); err != nil {
		return sourcePath(directory, source), legacy, fmt.Errorf("sync dnf backup cleanup: %w",
			directory.recordConflict("sync dnf backup cleanup", err))
	}
	return sourcePath(directory, source), legacy, nil
}

func readDNFMarkerSnapshot(directory *restoreDirectory, name string) (string, regularSnapshot, error) {
	snapshot, err := directory.readRegular(name, 256)
	if err != nil || !snapshot.exists {
		return "", snapshot, err
	}
	switch string(snapshot.data) {
	case dnf4AbsentContents:
		return "dnf4", snapshot, nil
	case dnf5AbsentContents:
		return "dnf5", snapshot, nil
	default:
		return "", regularSnapshot{}, errors.New("absence marker has invalid contents")
	}
}
