package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"open-go-dig/internal/dns"
)

var (
	localeKeyRe   = regexp.MustCompile(`(?m)^([a-z0-9_.]+):`)
	templateKeyRe = regexp.MustCompile(`\b(?:T|Tn) +"([a-z0-9_.]+)"`)
	goKeyRe       = regexp.MustCompile(`\.T\("([a-z0-9_.]+)"\)`)
)

// embeddedLocales returns the keys of each embedded locale file, by file name.
func embeddedLocales(t *testing.T) map[string]map[string]bool {
	t.Helper()
	entries, err := fs.ReadDir(localeFiles, "locales")
	if err != nil {
		t.Fatal(err)
	}
	locales := map[string]map[string]bool{}
	for _, e := range entries {
		data, err := fs.ReadFile(localeFiles, "locales/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		for _, m := range localeKeyRe.FindAllStringSubmatch(string(data), -1) {
			keys[m[1]] = true
		}
		if len(keys) == 0 {
			t.Fatalf("%s: no key found", e.Name())
		}
		locales[e.Name()] = keys
	}
	if len(locales) < 2 {
		t.Fatalf("found %d locale files", len(locales))
	}
	return locales
}

func TestLocalesHaveTheSameKeys(t *testing.T) {
	locales := embeddedLocales(t)
	union := map[string]bool{}
	for _, keys := range locales {
		for k := range keys {
			union[k] = true
		}
	}
	for file, keys := range locales {
		for k := range union {
			if !keys[k] {
				t.Errorf("%s: missing key %s", file, k)
			}
		}
	}
}

// The catalogue builds keys at runtime, so a grep of the templates cannot see them.
func TestCatalogueHasItsTranslations(t *testing.T) {
	for file, keys := range embeddedLocales(t) {
		for _, g := range dns.TypeCatalog {
			if k := "index.type_group_" + g.Key; !keys[k] {
				t.Errorf("%s: missing key %s", file, k)
			}
			for _, name := range g.Types {
				if k := "result.record_type_" + strings.ToLower(name); !keys[k] {
					t.Errorf("%s: missing key %s", file, k)
				}
			}
		}
	}
}

func TestTemplatesUseExistingKeys(t *testing.T) {
	locales := embeddedLocales(t)
	found := 0
	err := fs.WalkDir(templateFiles, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(templateFiles, path)
		if err != nil {
			return err
		}
		for _, m := range templateKeyRe.FindAllStringSubmatch(string(data), -1) {
			found++
			for file, keys := range locales {
				if !keys[m[1]] {
					t.Errorf("%s uses %s, missing from %s", path, m[1], file)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no translation key found in the templates: stale regexp?")
	}
}

func TestGoCodeUsesExistingKeys(t *testing.T) {
	locales := embeddedLocales(t)
	found := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range goKeyRe.FindAllStringSubmatch(string(data), -1) {
			found++
			for file, keys := range locales {
				if !keys[m[1]] {
					t.Errorf("%s uses %s, missing from %s", path, m[1], file)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no translation key found in the Go code: stale regexp?")
	}
}
