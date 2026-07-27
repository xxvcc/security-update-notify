// Package aptconfig contains the APT periodic policy shared by installation
// and fail-closed uninstall provenance checks.
package aptconfig

const Periodic = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
`
