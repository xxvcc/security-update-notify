package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/osrel"
)

const (
	transactionSchema      = 1
	transactionJournalName = "transaction.json"
	transactionStateActive = "active"
	transactionStateCommit = "committed"
	transactionStateRevert = "rolled_back"
	maxTransactionBytes    = 1 << 20

	plainCredentialRecoveryPath     = "/etc/security-update-notify/credentials/.feishu-app-secret.install-recovery"
	encryptedCredentialRecoveryPath = "/etc/credstore.encrypted/" +
		".security-update-notify-feishu-app-secret.cred.install-recovery"
)

type transactionPath struct {
	Path            string `json:"path"`
	Exists          bool   `json:"exists"`
	PreserveCurrent bool   `json:"preserve_current,omitempty"`
	SkipDependency  bool   `json:"skip_dependency_capture,omitempty"`
}

type transactionPrivateCredential struct {
	Path         string `json:"path"`
	RecoveryPath string `json:"recovery_path"`
	Exists       bool   `json:"exists"`
	Mode         uint32 `json:"mode,omitempty"`
}

type transactionTimer struct {
	Active     bool   `json:"active"`
	Enablement string `json:"enablement"`
}

type transactionUnit struct {
	Name       string `json:"name"`
	Active     bool   `json:"active"`
	Enablement string `json:"enablement"`
}

type transactionDependency struct {
	State          string   `json:"state"`
	Backend        string   `json:"backend"`
	Engine         string   `json:"engine"`
	AutomaticUnits []string `json:"automatic_units"`
}

type transactionJournal struct {
	Schema                 int                            `json:"schema"`
	State                  string                         `json:"state"`
	BackupDir              string                         `json:"backup_dir"`
	MutationStarted        bool                           `json:"mutation_started"`
	RecoverySafe           bool                           `json:"recovery_safe"`
	UnsafeReason           string                         `json:"unsafe_reason,omitempty"`
	Paths                  []transactionPath              `json:"paths"`
	PrivateCredentials     []transactionPrivateCredential `json:"private_credentials"`
	ProjectTimer           transactionTimer               `json:"project_timer"`
	AutomaticUnits         []transactionUnit              `json:"automatic_units,omitempty"`
	AutomaticUnitsCaptured bool                           `json:"automatic_units_captured"`
	Dependency             *transactionDependency         `json:"dependency,omitempty"`
}

type installTransaction struct {
	installer              *Installer
	path                   string
	journal                transactionJournal
	privateRecoveryCreated map[string]bool
}

func privateRecoveryPath(credentialPath string) string {
	switch credentialPath {
	case FeishuPlainCredentialPath:
		return plainCredentialRecoveryPath
	case FeishuEncryptedCredPath:
		return encryptedCredentialRecoveryPath
	default:
		return ""
	}
}

func (i *Installer) beginTransaction(b *backup, private map[string]privateSnapshot, timer timerSnapshot) (_ *installTransaction, returnErr error) {
	tx := &installTransaction{
		installer:              i,
		path:                   path.Join(b.dir, transactionJournalName),
		privateRecoveryCreated: make(map[string]bool, 2),
		journal: transactionJournal{
			Schema:             transactionSchema,
			State:              transactionStateActive,
			BackupDir:          b.dir,
			RecoverySafe:       true,
			ProjectTimer:       timerToTransaction(timer),
			PrivateCredentials: make([]transactionPrivateCredential, 0, 2),
		},
	}
	for _, credentialPath := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath} {
		snapshot := private[credentialPath]
		tx.journal.PrivateCredentials = append(tx.journal.PrivateCredentials, transactionPrivateCredential{
			Path: credentialPath, RecoveryPath: privateRecoveryPath(credentialPath),
			Exists: snapshot.exists, Mode: uint32(snapshot.mode.Perm()),
		})
	}
	b.transaction = tx
	tx.captureBackup(b)
	if err := tx.validatePrivateRecoveryTargets(); err != nil {
		b.transaction = nil
		return nil, err
	}
	if err := tx.write(); err != nil {
		b.transaction = nil
		return nil, err
	}
	complete := false
	defer func() {
		if complete {
			return
		}
		b.transaction = nil
		cleanupErr := tx.cleanupPrivateRecovery()
		if cleanupErr == nil {
			cleanupErr = tx.removeJournal()
		}
		returnErr = errors.Join(returnErr, cleanupErr)
	}()
	if err := tx.persistPrivateRecovery(private); err != nil {
		return nil, err
	}
	// This durable bit is written before quiescing a timer or changing any
	// managed path. Recovery may skip rollback only while it remains false.
	tx.journal.MutationStarted = true
	if err := tx.write(); err != nil {
		return nil, err
	}
	complete = true
	return tx, nil
}

func (tx *installTransaction) captureBackup(b *backup) {
	paths := make([]transactionPath, 0, len(b.paths))
	for _, name := range b.paths {
		snapshot := b.snapshots[name]
		paths = append(paths, transactionPath{
			Path: name, Exists: snapshot.exists, PreserveCurrent: snapshot.preserveCurrent,
			SkipDependency: b.skipDependencyCapturePath[name],
		})
	}
	tx.journal.Paths = paths
}

func (tx *installTransaction) syncBackup(b *backup) error {
	tx.captureBackup(b)
	return tx.write()
}

func (tx *installTransaction) markDependencyMutation(b *backup, plan installPlan) error {
	tx.captureBackup(b)
	tx.journal.RecoverySafe = false
	tx.journal.UnsafeReason = "package-manager state and retained defaults have not been reconciled"
	tx.journal.Dependency = &transactionDependency{
		State: "mutating", Backend: plan.backend, Engine: plan.profile.Engine,
		AutomaticUnits: automaticUnitNames(plan),
	}
	return tx.write()
}

func (tx *installTransaction) captureAutomaticUnits(units []unitSnapshot) error {
	tx.journal.AutomaticUnits = unitsToTransaction(units)
	tx.journal.AutomaticUnitsCaptured = true
	if tx.journal.Dependency != nil {
		tx.journal.Dependency.State = "retained"
		tx.journal.RecoverySafe = true
		tx.journal.UnsafeReason = ""
	}
	return tx.write()
}

func (tx *installTransaction) finish(state string) (bool, error) {
	if state != transactionStateCommit && state != transactionStateRevert {
		return false, failure("finalize installation transaction", fmt.Errorf("invalid final transaction state %q", state))
	}
	tx.journal.State = state
	if err := tx.write(); err != nil {
		return false, err
	}
	if err := tx.cleanupPrivateRecovery(); err != nil {
		return true, err
	}
	return true, tx.removeJournal()
}

func (tx *installTransaction) write() error {
	data, err := json.MarshalIndent(tx.journal, "", "  ")
	if err != nil {
		return failure("encode installation transaction journal", err)
	}
	data = append(data, '\n')
	if len(data) > maxTransactionBytes {
		return failure("encode installation transaction journal", errors.New("journal exceeds 1 MiB"))
	}
	if err := tx.installer.fs.WriteFileAtomic(tx.path, data, 0o600); err != nil {
		return failure("write installation transaction journal", err)
	}
	return nil
}

func (tx *installTransaction) persistPrivateRecovery(private map[string]privateSnapshot) error {
	// Check both fixed sibling names before writing either one. This prevents a
	// later conflict from being mistaken for transaction-owned cleanup after the
	// first recovery copy has already been published.
	if err := tx.validatePrivateRecoveryTargets(); err != nil {
		return err
	}
	for _, entry := range tx.journal.PrivateCredentials {
		if !entry.Exists {
			continue
		}
		snapshot := private[entry.Path]
		if err := tx.installer.fs.WriteFileAtomic(entry.RecoveryPath, snapshot.data, 0o600); err != nil {
			return failure("write private credential recovery", err)
		}
		tx.privateRecoveryCreated[entry.RecoveryPath] = true
		data, err := tx.installer.readPrivateRecovery(entry.RecoveryPath, privateLimit(entry.Path))
		if err != nil {
			return err
		}
		if !bytes.Equal(data, snapshot.data) {
			zeroBytes(data)
			return failure("verify private credential recovery", errors.New("recovery bytes differ from the credential snapshot"))
		}
		zeroBytes(data)
	}
	return nil
}

func (tx *installTransaction) validatePrivateRecoveryTargets() error {
	for _, entry := range tx.journal.PrivateCredentials {
		if exists, err := tx.installer.exists(entry.RecoveryPath); err != nil {
			return failure("inspect private credential recovery", err)
		} else if exists {
			return failure("prepare private credential recovery", fmt.Errorf("reserved recovery path already exists: %s", entry.RecoveryPath))
		}
	}
	for _, entry := range tx.journal.PrivateCredentials {
		if !entry.Exists {
			continue
		}
		// The original credential could only have been snapshotted through this
		// existing parent. Validate it without chmod or creation: the journal still
		// says MutationStarted=false, so a failed recovery copy must not leave an
		// untracked permission or directory change on the host.
		parent := path.Dir(entry.RecoveryPath)
		info, err := tx.installer.fs.Lstat(parent)
		if err != nil {
			return failure("prepare private credential recovery", err)
		}
		if err := tx.installer.validateManagedDir(parent, info, 0); err != nil {
			return failure("prepare private credential recovery", err)
		}
	}
	return nil
}

func privateLimit(credentialPath string) int64 {
	if credentialPath == FeishuEncryptedCredPath {
		return 128 << 10
	}
	return 64 << 10
}

func (i *Installer) readPrivateRecovery(name string, limit int64) ([]byte, error) {
	data, info, err := i.fs.ReadRegularFile(name, limit)
	if err != nil {
		return nil, failure("read private credential recovery", err)
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o077, true); err != nil {
		zeroBytes(data)
		return nil, failure("validate private credential recovery", err)
	}
	if info.Mode().Perm() != 0o600 {
		zeroBytes(data)
		return nil, failure("validate private credential recovery", fmt.Errorf("mode is %04o, want 0600", info.Mode().Perm()))
	}
	return data, nil
}

func (tx *installTransaction) cleanupPrivateRecovery() error {
	var errs []error
	for _, entry := range tx.journal.PrivateCredentials {
		if !entry.Exists {
			if exists, err := tx.installer.exists(entry.RecoveryPath); err != nil {
				errs = append(errs, failure("inspect absent private credential recovery", err))
			} else if exists {
				errs = append(errs, failure("inspect absent private credential recovery", fmt.Errorf(
					"unexpected reserved recovery file: %s", entry.RecoveryPath)))
			}
			continue
		}
		if tx.privateRecoveryCreated != nil && !tx.privateRecoveryCreated[entry.RecoveryPath] {
			if exists, err := tx.installer.exists(entry.RecoveryPath); err != nil {
				errs = append(errs, failure("inspect unowned private credential recovery", err))
			} else if exists {
				errs = append(errs, failure("inspect unowned private credential recovery", fmt.Errorf(
					"reserved recovery file was not created by this transaction: %s", entry.RecoveryPath)))
			}
			continue
		}
		if err := tx.installer.fs.Remove(entry.RecoveryPath); err != nil {
			errs = append(errs, failure("remove private credential recovery", err))
			continue
		}
		if err := tx.installer.syncExistingDirectory(path.Dir(entry.RecoveryPath)); err != nil {
			errs = append(errs, failure("sync private credential recovery directory", err))
		}
	}
	return errors.Join(errs...)
}

func (tx *installTransaction) removeJournal() error {
	if err := tx.installer.fs.Remove(tx.path); err != nil {
		return tx.retainJournalAfterCleanupFailure(failure("remove installation transaction journal", err))
	}
	if err := tx.installer.fs.SyncDir(path.Dir(tx.path)); err != nil {
		return tx.retainJournalAfterCleanupFailure(failure("sync installation transaction directory", err))
	}
	return nil
}

func (tx *installTransaction) retainJournalAfterCleanupFailure(cleanupErr error) error {
	exists, inspectErr := tx.installer.exists(tx.path)
	if inspectErr == nil && exists {
		return cleanupErr
	}
	writeErr := tx.write()
	if writeErr != nil {
		writeErr = failure("retain installation transaction journal after cleanup failure", writeErr)
	}
	if inspectErr != nil {
		inspectErr = failure("inspect installation transaction journal after cleanup failure", inspectErr)
	}
	return errors.Join(cleanupErr, inspectErr, writeErr)
}

func (i *Installer) syncExistingDirectory(name string) error {
	info, err := i.fs.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", name)
	}
	return i.fs.SyncDir(name)
}

func (i *Installer) recoverInterruptedTransaction(ctx context.Context, lockWait time.Duration) error {
	tx, b, err := i.loadTransaction()
	if err != nil || tx == nil {
		return err
	}
	switch tx.journal.State {
	case transactionStateCommit, transactionStateRevert:
		if err := tx.cleanupPrivateRecovery(); err != nil {
			return err
		}
		return tx.removeJournal()
	case transactionStateActive:
	default:
		return failure("recover interrupted installation", fmt.Errorf("invalid transaction state %q", tx.journal.State))
	}
	if !tx.journal.MutationStarted {
		if err := tx.cleanupPrivateRecovery(); err != nil {
			return err
		}
		return tx.removeJournal()
	}
	if !tx.journal.RecoverySafe {
		return failure("recover interrupted installation", fmt.Errorf(
			"transaction is not automatically recoverable: %s; package-manager state must be inspected and repaired before retrying",
			tx.journal.UnsafeReason))
	}
	if err := i.requireSystemd(); err != nil {
		return failure("recover interrupted installation", err)
	}
	runtimeLock, err := i.acquireRuntimeLock(ctx, lockWait)
	if err != nil {
		return err
	}
	defer runtimeLock.Unlock()
	private, err := i.loadPrivateRecovery(tx.journal.PrivateCredentials)
	if err != nil {
		return err
	}
	defer func() {
		for _, snapshot := range private {
			zeroBytes(snapshot.data)
		}
	}()
	timer := timerFromTransaction(tx.journal.ProjectTimer)
	units := unitsFromTransaction(tx.journal.AutomaticUnits)
	if err := i.restoreBackup(b, private, timer, units); err != nil {
		return failure("recover interrupted installation", err)
	}
	if _, err := tx.finish(transactionStateRevert); err != nil {
		return failure("finalize recovered installation", err)
	}
	return nil
}

func (i *Installer) loadPrivateRecovery(entries []transactionPrivateCredential) (map[string]privateSnapshot, error) {
	private := make(map[string]privateSnapshot, 2)
	fail := func(err error) (map[string]privateSnapshot, error) {
		for _, snapshot := range private {
			zeroBytes(snapshot.data)
		}
		return nil, err
	}
	for _, entry := range entries {
		if !entry.Exists {
			if exists, err := i.exists(entry.RecoveryPath); err != nil {
				return fail(failure("inspect absent private credential recovery", err))
			} else if exists {
				return fail(failure("inspect absent private credential recovery", fmt.Errorf(
					"unexpected reserved recovery file: %s", entry.RecoveryPath)))
			}
			private[entry.Path] = privateSnapshot{}
			continue
		}
		data, err := i.readPrivateRecovery(entry.RecoveryPath, privateLimit(entry.Path))
		if err != nil {
			return fail(err)
		}
		private[entry.Path] = privateSnapshot{exists: true, mode: fs.FileMode(entry.Mode), data: data}
	}
	return private, nil
}

func (i *Installer) loadTransaction() (*installTransaction, *backup, error) {
	rootInfo, err := i.fs.Lstat(BackupRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, i.rejectOrphanPrivateRecovery()
	}
	if err != nil {
		return nil, nil, failure("inspect installation transaction root", err)
	}
	if err := i.validateManagedDir(BackupRoot, rootInfo, 0o700); err != nil {
		return nil, nil, failure("inspect installation transaction root", err)
	}
	entries, err := i.fs.ReadDir(BackupRoot)
	if err != nil {
		return nil, nil, failure("scan installation transaction journals", err)
	}
	var found *installTransaction
	for _, entry := range entries {
		if !validTransactionBackupName(entry.Name()) {
			continue
		}
		directory := path.Join(BackupRoot, entry.Name())
		directoryInfo, err := i.fs.Lstat(directory)
		if err != nil {
			return nil, nil, failure("inspect backup directory during transaction scan", err)
		}
		if err := i.validateManagedDir(directory, directoryInfo, 0o700); err != nil {
			return nil, nil, failure("inspect backup directory during transaction scan", err)
		}
		journalPath := path.Join(directory, transactionJournalName)
		data, exists, err := i.readProtectedTransactionFile(journalPath, maxTransactionBytes, 0o600)
		if err != nil {
			return nil, nil, failure("read installation transaction journal", err)
		}
		if !exists {
			continue
		}
		if found != nil {
			return nil, nil, failure("scan installation transaction journals", errors.New("multiple transaction journals require manual inspection"))
		}
		journal, err := decodeTransactionJournal(data)
		if err != nil {
			return nil, nil, failure("decode installation transaction journal", err)
		}
		if err := i.validateTransactionJournal(journal, directory); err != nil {
			return nil, nil, failure("validate installation transaction journal", err)
		}
		for _, privateEntry := range journal.PrivateCredentials {
			recoveryExists, err := i.exists(privateEntry.RecoveryPath)
			if err != nil {
				return nil, nil, failure("inspect private credential recovery", err)
			}
			if !privateEntry.Exists && recoveryExists {
				return nil, nil, failure("validate installation transaction journal", fmt.Errorf(
					"absent credential has an unexpected reserved recovery file: %s", privateEntry.RecoveryPath))
			}
			mustExist := journal.State == transactionStateActive && journal.MutationStarted && privateEntry.Exists
			if privateEntry.Exists && (recoveryExists || mustExist) {
				private, err := i.readPrivateRecovery(privateEntry.RecoveryPath, privateLimit(privateEntry.Path))
				if err != nil {
					return nil, nil, err
				}
				zeroBytes(private)
			}
		}
		found = &installTransaction{installer: i, path: journalPath, journal: journal}
	}
	if found == nil {
		return nil, nil, i.rejectOrphanPrivateRecovery()
	}
	return found, backupFromTransaction(found), nil
}

func (i *Installer) readProtectedTransactionFile(name string, limit int64, mode fs.FileMode) ([]byte, bool, error) {
	data, info, err := i.fs.ReadRegularFile(name, limit)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o077, true); err != nil {
		return nil, false, err
	}
	if info.Mode().Perm() != mode.Perm() {
		return nil, false, fmt.Errorf("%s has mode %04o, want %04o", name, info.Mode().Perm(), mode.Perm())
	}
	return data, true, nil
}

func decodeTransactionJournal(data []byte) (transactionJournal, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal transactionJournal
	if err := decoder.Decode(&journal); err != nil {
		return transactionJournal{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("journal contains multiple JSON values")
		}
		return transactionJournal{}, err
	}
	return journal, nil
}

func (i *Installer) validateTransactionJournal(journal transactionJournal, directory string) error {
	if journal.Schema != transactionSchema || journal.BackupDir != directory {
		return errors.New("journal schema or backup directory does not match")
	}
	if journal.State != transactionStateActive && journal.State != transactionStateCommit && journal.State != transactionStateRevert {
		return fmt.Errorf("invalid journal state %q", journal.State)
	}
	if journal.RecoverySafe && journal.UnsafeReason != "" {
		return errors.New("recovery-safe journal has an unsafe reason")
	}
	if !journal.RecoverySafe && journal.UnsafeReason == "" {
		return errors.New("unsafe journal lacks a reason")
	}
	if !journal.MutationStarted {
		if journal.State != transactionStateActive || journal.Dependency != nil || journal.AutomaticUnitsCaptured ||
			journal.AutomaticUnits != nil || !journal.RecoverySafe {
			return errors.New("pre-mutation journal contains a later transaction phase")
		}
	}
	if journal.State != transactionStateActive && !journal.RecoverySafe {
		return errors.New("final transaction journal cannot be recovery-unsafe")
	}
	if journal.ProjectTimer.Enablement != "not-found" && !restorableProjectTimerEnablement(journal.ProjectTimer.Enablement) {
		return fmt.Errorf("project timer state %q is not restorable", journal.ProjectTimer.Enablement)
	}
	if journal.ProjectTimer.Enablement == "not-found" && journal.ProjectTimer.Active {
		return errors.New("missing project timer cannot be active")
	}
	seenPaths := make(map[string]bool, len(journal.Paths))
	for _, entry := range journal.Paths {
		if seenPaths[entry.Path] || !validTransactionPath(entry.Path) {
			return fmt.Errorf("invalid or duplicate transaction path %q", entry.Path)
		}
		seenPaths[entry.Path] = true
		if entry.Exists {
			backupPath := path.Join(directory, strings.TrimPrefix(entry.Path, "/"))
			if err := i.validateSnapshotCopySource(entry.Path, backupPath); err != nil {
				return err
			}
		}
		if entry.PreserveCurrent && (entry.Exists || entry.Path != aptPeriodicPath && entry.Path != dnfAutomaticPath) {
			return fmt.Errorf("invalid preserve-current snapshot for %s", entry.Path)
		}
	}
	for _, required := range managedPaths {
		if !seenPaths[required] {
			return fmt.Errorf("journal omits managed path %s", required)
		}
	}
	if err := validateTransactionPrivateEntries(journal.PrivateCredentials); err != nil {
		return err
	}
	seenUnits := make(map[string]bool)
	for _, unit := range journal.AutomaticUnits {
		if seenUnits[unit.Name] || !validAutomaticUnitName(unit.Name) || !restorableAutomaticEnablement(unit.Enablement) {
			return fmt.Errorf("invalid automatic-unit snapshot %q", unit.Name)
		}
		seenUnits[unit.Name] = true
		if unit.Enablement == "not-found" && unit.Active {
			return fmt.Errorf("missing automatic unit %s cannot be active", unit.Name)
		}
	}
	if journal.AutomaticUnitsCaptured != (journal.AutomaticUnits != nil) {
		return errors.New("automatic-unit capture marker does not match its snapshots")
	}
	if journal.AutomaticUnitsCaptured && len(journal.AutomaticUnits) == 0 {
		return errors.New("automatic-unit capture is empty")
	}
	if journal.Dependency != nil {
		if journal.Dependency.State != "mutating" && journal.Dependency.State != "retained" {
			return errors.New("invalid dependency transaction state")
		}
		if journal.Dependency.Backend != "apt" && journal.Dependency.Backend != "dnf" {
			return errors.New("invalid dependency transaction backend")
		}
		if !validDependencyUnits(journal.Dependency) {
			return errors.New("dependency transaction has invalid engine or automatic-unit set")
		}
		switch journal.Dependency.State {
		case "mutating":
			if journal.RecoverySafe {
				return errors.New("mutating dependency transaction cannot be recovery-safe")
			}
		case "retained":
			if !journal.RecoverySafe || !journal.AutomaticUnitsCaptured || !sameTransactionUnitNames(journal.AutomaticUnits, journal.Dependency.AutomaticUnits) {
				return errors.New("retained dependency transaction lacks its durable automatic-unit baseline")
			}
		}
	}
	if journal.Dependency == nil && !journal.RecoverySafe {
		return errors.New("journal without a dependency transaction cannot be unsafe")
	}
	if !journal.RecoverySafe && (journal.Dependency == nil || journal.Dependency.State != "mutating") {
		return errors.New("unsafe journal lacks a reconcilable dependency phase")
	}
	return nil
}

func validDependencyUnits(dependency *transactionDependency) bool {
	var expected []string
	switch dependency.Engine {
	case osrel.EngineAPT:
		if dependency.Backend != "apt" {
			return false
		}
		expected = []string{"apt-daily.timer", "apt-daily-upgrade.timer", "unattended-upgrades.service"}
	case osrel.EngineDNF4:
		if dependency.Backend != "dnf" {
			return false
		}
		expected = []string{"dnf-automatic.timer", "dnf-automatic-notifyonly.timer", "dnf-automatic-download.timer", "dnf-automatic-install.timer"}
	case osrel.EngineDNF5:
		if dependency.Backend != "dnf" {
			return false
		}
		expected = []string{"dnf5-automatic.timer", "dnf-automatic.timer"}
	default:
		return false
	}
	if len(expected) != len(dependency.AutomaticUnits) {
		return false
	}
	for index := range expected {
		if expected[index] != dependency.AutomaticUnits[index] {
			return false
		}
	}
	return true
}

func sameTransactionUnitNames(units []transactionUnit, names []string) bool {
	if len(units) != len(names) {
		return false
	}
	for index := range units {
		if units[index].Name != names[index] {
			return false
		}
	}
	return true
}

func validateTransactionPrivateEntries(entries []transactionPrivateCredential) error {
	if len(entries) != 2 {
		return errors.New("journal must describe exactly two private credential paths")
	}
	seen := make(map[string]bool, 2)
	for _, entry := range entries {
		if seen[entry.Path] || privateRecoveryPath(entry.Path) == "" || entry.RecoveryPath != privateRecoveryPath(entry.Path) {
			return fmt.Errorf("invalid private credential recovery entry %q", entry.Path)
		}
		seen[entry.Path] = true
		if entry.Exists && fs.FileMode(entry.Mode).Perm()&0o077 != 0 {
			return fmt.Errorf("private credential mode %04o is not protected", entry.Mode)
		}
		if !entry.Exists && entry.Mode != 0 {
			return errors.New("absent private credential has a mode")
		}
	}
	return nil
}

func (i *Installer) rejectOrphanPrivateRecovery() error {
	for _, name := range []string{encryptedCredentialRecoveryPath, plainCredentialRecoveryPath} {
		if exists, err := i.exists(name); err != nil {
			return failure("inspect private credential recovery", err)
		} else if exists {
			return failure("inspect private credential recovery", fmt.Errorf("orphaned reserved recovery file requires manual inspection: %s", name))
		}
	}
	return nil
}

func backupFromTransaction(tx *installTransaction) *backup {
	b := &backup{
		dir: tx.journal.BackupDir, paths: make([]string, 0, len(tx.journal.Paths)),
		snapshots:                 make(map[string]nodeSnapshot, len(tx.journal.Paths)),
		skipDependencyCapturePath: make(map[string]bool), transaction: tx,
	}
	for _, entry := range tx.journal.Paths {
		snapshot := nodeSnapshot{exists: entry.Exists, preserveCurrent: entry.PreserveCurrent}
		if entry.Exists {
			snapshot.backupPath = path.Join(b.dir, strings.TrimPrefix(entry.Path, "/"))
			b.manifest = append(b.manifest, strings.TrimPrefix(entry.Path, "/"))
		}
		b.paths = append(b.paths, entry.Path)
		b.snapshots[entry.Path] = snapshot
		b.skipDependencyCapturePath[entry.Path] = entry.SkipDependency
	}
	return b
}

func timerToTransaction(timer timerSnapshot) transactionTimer {
	return transactionTimer{Active: timer.active, Enablement: timer.enablement}
}

func timerFromTransaction(timer transactionTimer) timerSnapshot {
	return timerSnapshot{active: timer.Active, enablement: timer.Enablement}
}

func unitsToTransaction(units []unitSnapshot) []transactionUnit {
	result := make([]transactionUnit, 0, len(units))
	for _, unit := range units {
		result = append(result, transactionUnit{Name: unit.name, Active: unit.active, Enablement: unit.enablement})
	}
	return result
}

func unitsFromTransaction(units []transactionUnit) []unitSnapshot {
	result := make([]unitSnapshot, 0, len(units))
	for _, unit := range units {
		result = append(result, unitSnapshot{name: unit.Name, active: unit.Active, enablement: unit.Enablement})
	}
	return result
}

func validTransactionBackupName(name string) bool {
	stamp := name
	if len(name) == len("20060102150405-000") && name[len("20060102150405")] == '-' {
		stamp = name[:len("20060102150405")]
		for _, value := range name[len("20060102150405-"):] {
			if value < '0' || value > '9' {
				return false
			}
		}
	}
	return validBackupTimestamp(stamp) && (len(name) == len(stamp) || len(name) == len("20060102150405-000"))
}

func validTransactionPath(name string) bool {
	if name == "" || path.Clean(name) != name || !path.IsAbs(name) {
		return false
	}
	for _, allowed := range managedPaths {
		if name == allowed {
			return true
		}
	}
	for _, channel := range []string{"telegram", "feishu"} {
		for _, allowed := range deliveryStatePaths(channel) {
			if name == allowed {
				return true
			}
		}
	}
	base := path.Base(name)
	directory := path.Dir(name)
	aptBase := path.Base(aptPeriodicPath)
	if directory == path.Dir(aptPeriodicPath) {
		if strings.HasPrefix(base, aptBase+".security-update-notify.") && strings.HasSuffix(base, ".bak") {
			stamp := strings.TrimSuffix(strings.TrimPrefix(base, aptBase+".security-update-notify."), ".bak")
			return validBackupTimestamp(stamp)
		}
		if strings.HasPrefix(base, path.Base(aptStableBackupPath)+".") {
			return validBackupTimestamp(strings.TrimPrefix(base, path.Base(aptStableBackupPath)+"."))
		}
	}
	if directory == path.Dir(dnfAutomaticPath) && strings.HasPrefix(base, path.Base(dnfStableBackupPath)+".") {
		return validBackupTimestamp(strings.TrimPrefix(base, path.Base(dnfStableBackupPath)+"."))
	}
	return false
}

func validAutomaticUnitName(name string) bool {
	switch name {
	case "apt-daily.timer", "apt-daily-upgrade.timer", "unattended-upgrades.service",
		"dnf-automatic.timer", "dnf-automatic-notifyonly.timer", "dnf-automatic-download.timer",
		"dnf-automatic-install.timer", "dnf5-automatic.timer":
		return true
	default:
		return false
	}
}
