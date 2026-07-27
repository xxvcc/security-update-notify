// Package dependencyproof creates content-bound provenance records for files
// produced by retained package-manager transactions.
package dependencyproof

import (
	"crypto/sha256"
	"fmt"
)

// Contents returns the canonical proof for one backend and exact file content.
func Contents(backend string, content []byte) []byte {
	digest := sha256.Sum256(content)
	return []byte(fmt.Sprintf("security-update-notify: %s dependency default sha256=%x\n", backend, digest))
}
