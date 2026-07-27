package dependencyproof

import (
	"bytes"
	"testing"
)

func TestContentsIsBackendAndContentBound(t *testing.T) {
	content := []byte("default\n")
	want := []byte("security-update-notify: apt dependency default sha256=01666ec060466c14b9fa06c613fbac449163f2a2017558fe16526209ab78c6b0\n")
	if got := Contents("apt", content); !bytes.Equal(got, want) {
		t.Fatalf("Contents() = %q, want %q", got, want)
	}
	if bytes.Equal(Contents("dnf", content), want) {
		t.Fatal("Contents() did not bind the backend")
	}
	if bytes.Equal(Contents("apt", append(content, '\n')), want) {
		t.Fatal("Contents() did not bind the file content")
	}
}
