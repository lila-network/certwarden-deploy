package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfigFile creates path including all parent directories.
func writeConfigFile(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create directory for %v: %v", path, err)
	}

	if err := os.WriteFile(path, []byte("base_url: \"https://thisisatest.invalid\"\n"), 0644); err != nil {
		t.Fatalf("failed to write file %v: %v", path, err)
	}
}

// isolateEnvironment points the working directory, XDG_CONFIG_HOME and HOME at
// empty temporary directories, so no test depends on the real environment.
func isolateEnvironment(t *testing.T) (workDir string, xdgDir string, homeDir string) {
	t.Helper()

	workDir = t.TempDir()
	xdgDir = t.TempDir()
	homeDir = t.TempDir()

	t.Chdir(workDir)
	t.Setenv("XDG_CONFIG_HOME", xdgDir)
	t.Setenv("HOME", homeDir)

	return workDir, xdgDir, homeDir
}

func TestDiscoverConfigFilePrefersWorkingDirectory(t *testing.T) {
	_, xdgDir, _ := isolateEnvironment(t)
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	writeConfigFile(t, localConfigFile)
	writeConfigFile(t, filepath.Join(xdgDir, userConfigFile))
	writeConfigFile(t, systemPath)

	path, err := discoverConfigFile(defaultConfigPaths(systemPath))
	if err != nil {
		t.Fatalf("got error discovering config file: %v", err.Error())
	}

	if path != localConfigFile {
		t.Errorf("got \"%v\", want \"%v\"", path, localConfigFile)
	}
}

func TestDiscoverConfigFileRespectsXdgConfigHome(t *testing.T) {
	_, xdgDir, homeDir := isolateEnvironment(t)
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	expectedPath := filepath.Join(xdgDir, userConfigFile)
	writeConfigFile(t, expectedPath)
	writeConfigFile(t, filepath.Join(homeDir, ".config", userConfigFile))
	writeConfigFile(t, systemPath)

	path, err := discoverConfigFile(defaultConfigPaths(systemPath))
	if err != nil {
		t.Fatalf("got error discovering config file: %v", err.Error())
	}

	if path != expectedPath {
		t.Errorf("got \"%v\", want \"%v\"", path, expectedPath)
	}
}

func TestDiscoverConfigFileFallsBackToHomeConfigDir(t *testing.T) {
	_, _, homeDir := isolateEnvironment(t)
	t.Setenv("XDG_CONFIG_HOME", "")
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	expectedPath := filepath.Join(homeDir, ".config", userConfigFile)
	writeConfigFile(t, expectedPath)
	writeConfigFile(t, systemPath)

	path, err := discoverConfigFile(defaultConfigPaths(systemPath))
	if err != nil {
		t.Fatalf("got error discovering config file: %v", err.Error())
	}

	if path != expectedPath {
		t.Errorf("got \"%v\", want \"%v\"", path, expectedPath)
	}
}

// TestDiscoverConfigFileUsesSystemPathAsLastResort also covers backwards
// compatibility: with only the system path present, the previously hard-coded
// default is still what gets loaded.
func TestDiscoverConfigFileUsesSystemPathAsLastResort(t *testing.T) {
	isolateEnvironment(t)
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	writeConfigFile(t, systemPath)

	path, err := discoverConfigFile(defaultConfigPaths(systemPath))
	if err != nil {
		t.Fatalf("got error discovering config file: %v", err.Error())
	}

	if path != systemPath {
		t.Errorf("got \"%v\", want \"%v\"", path, systemPath)
	}
}

func TestDiscoverConfigFileErrorListsAllSearchedPaths(t *testing.T) {
	_, xdgDir, _ := isolateEnvironment(t)
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	searchedPaths := defaultConfigPaths(systemPath)

	path, err := discoverConfigFile(searchedPaths)
	if err == nil {
		t.Fatalf("expected error without any config file, got \"%v\"", path)
	}

	if path != "" {
		t.Errorf("expected empty path on error, got \"%v\"", path)
	}

	for _, wanted := range append(searchedPaths, filepath.Join(xdgDir, userConfigFile)) {
		if !strings.Contains(err.Error(), wanted) {
			t.Errorf("error message does not mention searched path \"%v\": %v", wanted, err.Error())
		}
	}
}

func TestDefaultConfigPathsOrder(t *testing.T) {
	_, xdgDir, _ := isolateEnvironment(t)
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	expectedPaths := []string{
		localConfigFile,
		filepath.Join(xdgDir, userConfigFile),
		systemPath,
	}

	paths := defaultConfigPaths(systemPath)

	if len(paths) != len(expectedPaths) {
		t.Fatalf("got %v paths, want %v: %v", len(paths), len(expectedPaths), paths)
	}

	for i, wanted := range expectedPaths {
		if paths[i] != wanted {
			t.Errorf("path %v: got \"%v\", want \"%v\"", i, paths[i], wanted)
		}
	}
}

func TestDiscoverConfigFileIgnoresDirectories(t *testing.T) {
	isolateEnvironment(t)
	systemPath := filepath.Join(t.TempDir(), "config.yaml")

	if err := os.MkdirAll(localConfigFile, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	writeConfigFile(t, systemPath)

	path, err := discoverConfigFile(defaultConfigPaths(systemPath))
	if err != nil {
		t.Fatalf("got error discovering config file: %v", err.Error())
	}

	if path != systemPath {
		t.Errorf("got \"%v\", want \"%v\"", path, systemPath)
	}
}
