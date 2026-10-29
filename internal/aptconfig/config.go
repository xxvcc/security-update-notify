// Package aptconfig contains the APT periodic policy shared by installation
// and fail-closed uninstall provenance checks.
package aptconfig

import "bytes"

const Periodic = `APT::Periodic::Enable "1";
` + LegacyPeriodic

// LegacyPeriodic remains recognizable when restoring pre-3.3.3 SUN backups.
const LegacyPeriodic = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
`

func IsManagedPeriodic(content []byte) bool {
	return bytes.Equal(content, []byte(Periodic)) || bytes.Equal(content, []byte(LegacyPeriodic))
}

// LegacyLocalPolicy is the exact unattended-upgrades policy that SUN 1.1.x
// wrote to /etc/apt/apt.conf.d/52unattended-upgrades-local. Releases from 1.2
// onwards write 52unattended-upgrades-security-update-notify instead and only
// clean the old name up, so purge must match these bytes before removing it:
// on a host that never ran 1.1.x the same path is an administrator's own file.
// The 1.1.x installer used a quoted heredoc, so ${distro_codename} is literal.
const LegacyLocalPolicy = `// Local policy: install Debian/Ubuntu security updates automatically, do not reboot automatically.
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
