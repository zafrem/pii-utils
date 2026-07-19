// Package tests holds aggregate, black-box unit tests for grep-aws-s3. They live
// inside the module (not at the repo root) because the tool's packages are under
// internal/, which Go only lets code rooted at the grep-aws-s3 module import.
// Each test exercises the packages through their exported APIs, the way main.go
// wires them together.
package tests

import (
	"os"
	"path/filepath"
	"testing"
)

// regexDir locates the pii-pattern-engine regex rules relative to this package,
// skipping the test when the submodule is not checked out.
func regexDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "pii-pattern-engine", "regex")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("pattern submodule not available at %s: %v", dir, err)
	}
	return dir
}
