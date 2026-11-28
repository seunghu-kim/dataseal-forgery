package attackrun

import (
	"path/filepath"
	"runtime"
)

// ValidatorPaths returns the default schema and executable under tools/validator.
func ValidatorPaths(root string) (schema, exe string) {
	dir := filepath.Join(root, "tools", "validator")
	exe = filepath.Join(dir, "validator")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	return filepath.Join(dir, "schema.json"), exe
}
