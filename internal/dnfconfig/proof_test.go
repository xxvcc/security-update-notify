package dnfconfig

import (
	"bytes"
	"testing"
)

func TestDependencyDefaultProofIsContentBound(t *testing.T) {
	config := []byte("[commands]\napply_updates = no\n")
	want := []byte("security-update-notify: dnf dependency default sha256=33cb4b33d89e4b477d865b1a0b84989ca277875e2cb9dd4dce7c9dddec7d3962\n")
	if got := DependencyDefaultProof(config); !bytes.Equal(got, want) {
		t.Fatalf("DependencyDefaultProof() = %q, want %q", got, want)
	}
	if bytes.Equal(DependencyDefaultProof(append(config, '\n')), want) {
		t.Fatal("DependencyDefaultProof() did not change with the configuration")
	}
}
