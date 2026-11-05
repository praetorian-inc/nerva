package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllServicePluginsRegistered guards against a recurring bug: a service
// plugin is implemented with an init() that calls plugins.RegisterPlugin, but
// its package is never blank-imported in plugin_list.go, so init() never runs
// and the plugin is silently disabled. For every package under
// pkg/plugins/services that contains a RegisterPlugin call, this test asserts
// the package is blank-imported (name "_") in plugin_list.go. Comments and
// other non-import text do not count.
func TestAllServicePluginsRegistered(t *testing.T) {
	const importPrefix = "github.com/praetorian-inc/nerva/pkg/plugins/services/"
	servicesDir := filepath.Join("..", "plugins", "services")

	listBytes, err := os.ReadFile("plugin_list.go")
	if err != nil {
		t.Fatalf("read plugin_list.go: %v", err)
	}

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
		calls, err := sourceCallsRegisterPlugin(path, src)
		if err != nil {
			return err
		}
		if !calls {
			return nil
		}
		rel, err := filepath.Rel(servicesDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		importPath := importPrefix + filepath.ToSlash(rel)
		blank, err := hasBlankImport("plugin_list.go", listBytes, importPath)
		if err != nil {
			return err
		}
		if !blank {
			t.Errorf("service package %q calls plugins.RegisterPlugin but is not blank-imported in pkg/scan/plugin_list.go; add:\n\t_ %q", rel, importPath)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", servicesDir, walkErr)
	}
}

func TestCommentedImportPathNotCounted(t *testing.T) {
	const importPath = "github.com/praetorian-inc/nerva/pkg/plugins/services/example"
	commented := "package scan\n\n// _ \"" + importPath + "\"\n"
	got, err := hasBlankImport("plugin_list.go", []byte(commented), importPath)
	require.NoError(t, err)
	assert.False(t, got)

	named := "package scan\n\nimport svc \"" + importPath + "\"\n"
	got, err = hasBlankImport("plugin_list.go", []byte(named), importPath)
	require.NoError(t, err)
	assert.False(t, got)

	blank := "package scan\n\nimport _ \"" + importPath + "\"\n"
	got, err = hasBlankImport("plugin_list.go", []byte(blank), importPath)
	require.NoError(t, err)
	assert.True(t, got)
}

func TestCommentedRegisterPluginNotCall(t *testing.T) {
	commented := "package svc\n\n// plugins.RegisterPlugin(\n"
	got, err := sourceCallsRegisterPlugin("svc.go", []byte(commented))
	require.NoError(t, err)
	assert.False(t, got)

	called := "package svc\n\nfunc init() { plugins.RegisterPlugin(nil) }\n"
	got, err = sourceCallsRegisterPlugin("svc.go", []byte(called))
	require.NoError(t, err)
	assert.True(t, got)
}

func sourceCallsRegisterPlugin(filename string, src []byte) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.SkipObjectResolution)
	if err != nil {
		return false, err
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isRegisterPluginCall(call.Fun) {
			found = true
			return false
		}
		return true
	})
	return found, nil
}

func isRegisterPluginCall(fun ast.Expr) bool {
	switch fn := fun.(type) {
	case *ast.Ident:
		return fn.Name == "RegisterPlugin"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "RegisterPlugin"
	default:
		return false
	}
}

func hasBlankImport(filename string, src []byte, importPath string) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.SkipObjectResolution)
	if err != nil {
		return false, err
	}
	for _, imp := range f.Imports {
		if imp.Name == nil || imp.Name.Name != "_" {
			continue
		}
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return false, err
		}
		if path == importPath {
			return true, nil
		}
	}
	return false, nil
}
