package installer

import (
	"bytes"

	"errors"
	"fmt"
	"io/fs"

	"path"

	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/osrel"
)

func (i *Installer) validDNFAbsentMarkerAt(markerPath, engine string) (bool, error) {
	contents, err := dnfAbsentMarkerContentsFor(engine)
	if err != nil {
		return false, err
	}
	return i.validAbsentMarkerAt(markerPath, contents, "dnf")
}

func (i *Installer) validAbsentMarkerAt(markerPath, contents, backend string) (bool, error) {
	data, exists, err := i.readTrustedRegularFile(markerPath, 256)
	if err != nil || !exists {
		return exists, err
	}
	if string(data) != contents {
		return false, fmt.Errorf("%s absence marker has invalid contents", backend)
	}
	return true, nil
}

func dnfAbsentMarkerContentsFor(engine string) (string, error) {
	switch engine {
	case osrel.EngineDNF4:
		return dnfAbsentMarkerContents, nil
	case osrel.EngineDNF5:
		return dnf5AbsentMarkerContents, nil
	default:
		return "", fmt.Errorf("unsupported DNF engine %q", engine)
	}
}

func (i *Installer) recordDNFAbsentBaseline(plan installPlan) error {
	if err := i.ensureDir(path.Dir(dnfAbsentMarkerPath), 0o755); err != nil {
		return failure("create dnf configuration directory", err)
	}
	contents, err := dnfAbsentMarkerContentsFor(plan.profile.Engine)
	if err != nil {
		return failure("record absent dnf automatic config", err)
	}
	stable, err := i.validBaselineFile(dnfStableBackupPath)
	if err != nil {
		return failure("inspect stable dnf backup", err)
	}
	marker, err := i.validDNFAbsentMarkerAt(dnfAbsentMarkerPath, plan.profile.Engine)
	if err != nil {
		return failure("inspect dnf absence marker", err)
	}
	if stable || marker {
		return nil
	}
	if err := i.fs.WriteFileAtomic(dnfAbsentMarkerPath, []byte(contents), 0o600); err != nil {
		return failure("record absent dnf automatic config", err)
	}
	return nil
}

// recordDNF4DependencyProof binds a retained configuration to the DNF4 package
// transaction that created it. A retry can then promote the exact bytes
// without inferring provenance from INI values.
func (i *Installer) recordDNF4DependencyProof(plan installPlan) error {
	if plan.profile.Engine != osrel.EngineDNF4 {
		return nil
	}
	data, exists, err := i.readTrustedRegularFile(dnfAutomaticPath, 4<<20)
	if err != nil {
		return failure("inspect partial dnf dependency config", err)
	}
	if !exists {
		return nil
	}
	if _, err := parseStrictINI(data); err != nil {
		return failure("validate partial dnf dependency config", err)
	}
	matched, err := i.validDNFDependencyProof(data)
	if err != nil {
		return failure("inspect dnf dependency proof", err)
	}
	if matched {
		return nil
	}
	if err := i.fs.WriteFileAtomic(dnfDependencyProofPath, dnfDependencyProofContents(data), 0o600); err != nil {
		return failure("record dnf dependency proof", err)
	}
	return nil
}

func dnfDependencyProofContents(data []byte) []byte {
	return dnfconfig.DependencyDefaultProof(data)
}

func (i *Installer) validDNFDependencyProof(config []byte) (bool, error) {
	proof, exists, err := i.readTrustedRegularFile(dnfDependencyProofPath, 256)
	if err != nil || !exists {
		return exists, err
	}
	if !bytes.Equal(proof, dnfDependencyProofContents(config)) {
		return false, errors.New("dnf dependency proof does not match automatic.conf")
	}
	return true, nil
}

// persistDNF4DependencyBaseline keeps the vendor configuration created by the
// retained dnf-automatic package. Older SUN installations can already have an
// absence marker beside a managed current file; their earliest timestamped
// backup is the only safe source because the current file is no longer vendor
// state. DNF5 intentionally keeps its absence marker and packaged fallback.
func (i *Installer) persistDNF4DependencyBaseline(plan installPlan, b *backup, configOriginallyAbsent bool) error {
	if plan.profile.Engine != osrel.EngineDNF4 {
		return nil
	}
	marker, err := i.validDNFAbsentMarkerAt(dnfAbsentMarkerPath, plan.profile.Engine)
	if err != nil {
		return failure("inspect dnf absence marker after dependencies", err)
	}
	if !marker {
		return nil
	}
	configExists, err := i.validBaselineFile(dnfAutomaticPath)
	if err != nil {
		return failure("inspect dependency-created dnf automatic config", err)
	}
	stable, err := i.validBaselineFile(dnfStableBackupPath)
	if err != nil {
		return failure("inspect stable dnf backup after dependencies", err)
	}
	if !stable {
		baseline, err := i.oldestDNFProjectBackup()
		if err != nil {
			return failure("select original dnf backup after dependencies", err)
		}
		if baseline == "" {
			if !configExists {
				return failure("persist dnf vendor baseline", errors.New(
					"/etc/dnf/automatic.conf is missing after dependency verification; purge the incomplete SUN metadata, then reinstall dnf-automatic or restore a trusted vendor baseline before retrying"))
			}
			baseline = dnfAutomaticPath
		}
		data, baselineExists, err := i.readTrustedRegularFile(baseline, 4<<20)
		if err != nil || !baselineExists {
			if err == nil {
				err = fs.ErrNotExist
			}
			return failure("read dnf vendor baseline", err)
		}
		if _, err := parseStrictINI(data); err != nil {
			return failure("validate dnf vendor baseline", err)
		}
		if baseline == dnfAutomaticPath && !configOriginallyAbsent {
			proven, err := i.validDNFDependencyProof(data)
			if err != nil {
				return failure("validate dnf dependency proof", err)
			}
			if !proven {
				return failure("persist dnf vendor baseline", errors.New(
					"cannot prove that /etc/dnf/automatic.conf is a retained dependency default; restore a trusted vendor baseline before retrying"))
			}
		}
		if err := i.copyNode(baseline, dnfStableBackupPath); err != nil {
			return failure("persist dnf vendor baseline", err)
		}
		// The stable file did not exist in the pre-install snapshot. Capture it
		// now so a later SUN failure keeps the retained package usable.
		if err := i.captureDependencyDefaults(b); err != nil {
			return err
		}
	}
	for _, metadata := range []struct {
		path string
		op   string
	}{
		{path: dnfAbsentMarkerPath, op: "replace dnf absence marker with vendor baseline"},
		{path: dnfDependencyProofPath, op: "remove promoted dnf dependency proof"},
	} {
		// Persist the logical absence first so an abrupt stop cannot recover the
		// superseded marker beside the retained vendor baseline.
		if err := i.keepPathAbsentOnRollback(b, metadata.path); err != nil {
			return err
		}
		if err := i.fs.Remove(metadata.path); err != nil {
			return failure(metadata.op, err)
		}
	}
	return nil
}

func (i *Installer) validBaselineFile(name string) (bool, error) {
	_, exists, err := i.readTrustedRegularFile(name, 4<<20)
	return exists, err
}

// readTrustedRegularFile validates the metadata returned by the opened inode,
// not a preceding pathname lookup. Baselines and provenance records can affect
// what privileged configuration is preserved or restored, so writable,
// foreign-owned, or hard-linked files must never participate in that decision.
func (i *Installer) readTrustedRegularFile(name string, maxBytes int64) ([]byte, bool, error) {
	data, info, err := i.fs.ReadRegularFile(name, maxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o022, true); err != nil {
		return nil, false, fmt.Errorf("%s must be a protected root-owned regular file with one hard link: %w", name, err)
	}
	return data, true, nil
}
