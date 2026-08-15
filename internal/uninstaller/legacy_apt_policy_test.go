package uninstaller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
)

func TestPurgeRemovesLegacyAPTLocalPolicyWrittenByOneOneReleases(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptLegacyLocalPolicyLogical, aptconfig.LegacyLocalPolicy)

	if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
		t.Fatalf("Uninstall(purge) error = %v", err)
	}
	assertMissing(t, root, aptLegacyLocalPolicyLogical)
	assertLegacyAPTPolicyDirectory(t, root)
}

func TestPurgePreservesAdministratorFileAtLegacyAPTLocalPolicyPath(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{
			name:     "unrelated administrator policy",
			contents: "Unattended-Upgrade::Mail \"root\";\n",
		},
		{
			name:     "legacy policy with an administrator edit appended",
			contents: aptconfig.LegacyLocalPolicy + "Unattended-Upgrade::Automatic-Reboot-Time \"03:00\";\n",
		},
		{
			name:     "legacy policy without its trailing newline",
			contents: aptconfig.LegacyLocalPolicy[:len(aptconfig.LegacyLocalPolicy)-1],
		},
		{
			name:     "empty file",
			contents: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeFixture(t, root, aptLegacyLocalPolicyLogical, test.contents)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
				t.Fatalf("Uninstall(purge) error = %v", err)
			}
			assertContent(t, root, aptLegacyLocalPolicyLogical, test.contents)
			after, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			// Anything but the untouched original inode would mean purge claimed
			// and republished a file it has no provenance for.
			if !os.SameFile(before, after) {
				t.Fatal("administrator policy was replaced instead of left alone")
			}
			assertLegacyAPTPolicyDirectory(t, root, filepath.Base(aptLegacyLocalPolicyLogical))
		})
	}
}

func TestPurgeLeavesNonRegularLegacyAPTLocalPolicyEntryUntouched(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		verify  func(*testing.T, string)
	}{
		{
			name: "directory",
			prepare: func(t *testing.T, root string) {
				writeFixture(t, root, aptLegacyLocalPolicyLogical+"/administrator.conf", "administrator policy")
			},
			verify: func(t *testing.T, root string) {
				info, err := os.Lstat(hostPath(root, aptLegacyLocalPolicyLogical))
				if err != nil {
					t.Fatal(err)
				}
				if !info.IsDir() {
					t.Fatalf("legacy policy path mode = %v, want a directory", info.Mode())
				}
				assertContent(t, root, aptLegacyLocalPolicyLogical+"/administrator.conf", "administrator policy")
			},
		},
		{
			name: "symbolic link",
			prepare: func(t *testing.T, root string) {
				target := writeFixture(t, root, "/etc/administrator-unattended-upgrades", "administrator policy")
				path := hostPath(root, aptLegacyLocalPolicyLogical)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, root string) {
				info, err := os.Lstat(hostPath(root, aptLegacyLocalPolicyLogical))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("legacy policy path mode = %v, want a symbolic link", info.Mode())
				}
				assertContent(t, root, "/etc/administrator-unattended-upgrades", "administrator policy")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.prepare(t, root)

			if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
				t.Fatalf("Uninstall(purge) error = %v", err)
			}
			test.verify(t, root)
			assertLegacyAPTPolicyDirectory(t, root, filepath.Base(aptLegacyLocalPolicyLogical))
		})
	}
}

// TestLegacyAPTLocalPolicyMatchesTheOneOneInstallerHeredoc pins the constant to
// the ground truth it claims to reproduce: the quoted heredoc that install.sh
// wrote to 52unattended-upgrades-local in 1.1.x (git show fc0f625:install.sh).
// The quoting is why ${distro_codename} stays literal, and the indentation is
// part of the bytes, so any reflow of this constant stops purge from
// recognising the artifact it exists to clean up.
func TestLegacyAPTLocalPolicyMatchesTheOneOneInstallerHeredoc(t *testing.T) {
	const installed = `// Local policy: install Debian/Ubuntu security updates automatically, do not reboot automatically.
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Ubuntu,archive=${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::SyslogEnable "true";
`

	if aptconfig.LegacyLocalPolicy != installed {
		t.Fatalf("LegacyLocalPolicy = %q, want the 1.1.x installer heredoc %q", aptconfig.LegacyLocalPolicy, installed)
	}
}

// assertLegacyAPTPolicyDirectory reports the apt.conf.d listing so a retained
// quarantine or recovery marker fails the test instead of hiding behind a
// correct-looking policy file.
func assertLegacyAPTPolicyDirectory(t *testing.T, root string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(hostPath(root, filepath.Dir(aptLegacyLocalPolicyLogical)))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != len(want) {
		t.Fatalf("apt configuration directory = %v, want %v", names, want)
	}
	for index, name := range names {
		if name != want[index] {
			t.Fatalf("apt configuration directory = %v, want %v", names, want)
		}
	}
}
