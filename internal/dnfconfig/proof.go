package dnfconfig

import "github.com/xxvcc/security-update-notify/internal/dependencyproof"

// DependencyDefaultProof binds a retained DNF configuration to the package
// transaction that created it.
func DependencyDefaultProof(config []byte) []byte {
	return dependencyproof.Contents("dnf", config)
}
