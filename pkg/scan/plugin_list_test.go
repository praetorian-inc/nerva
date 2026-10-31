package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllServicePluginsRegistered guards against a recurring bug: a service
// plugin is implemented with an init() that calls plugins.RegisterPlugin, but
// its package is never blank-imported in plugin_list.go, so init() never runs
// and the plugin is silently disabled. For every package under
// pkg/plugins/services that calls plugins.RegisterPlugin, this test asserts the
// package is blank-imported in plugin_list.go.
func TestAllServicePluginsRegistered(t *testing.T) {
	const importPrefix = "github.com/praetorian-inc/nerva/pkg/plugins/services/"
	servicesDir := filepath.Join("..", "plugins", "services")

	listBytes, err := os.ReadFile("plugin_list.go")
	if err != nil {
		t.Fatalf("read plugin_list.go: %v", err)
	}
	list := string(listBytes)

	walkErr := filepath.WalkDir(servicesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), "plugins.RegisterPlugin(") {
			return nil
		}
		rel, err := filepath.Rel(servicesDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		importPath := importPrefix + filepath.ToSlash(rel)
		if !strings.Contains(list, `"`+importPath+`"`) {
			t.Errorf("service package %q calls plugins.RegisterPlugin but is not blank-imported in pkg/scan/plugin_list.go; add:\n\t_ %q", rel, importPath)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", servicesDir, walkErr)
	}
}
