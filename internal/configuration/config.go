package configuration

import (
	"fmt"
	"net/http"
	"os"

	"github.com/goccy/go-yaml"
)

// HTTPClient is a generic Interface for HTTP Clients
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ConfigLoader interface {
	readDataFromFile() ([]byte, error)
	unmarshalDataToConfig(data []byte) (ConfigFileData, error)
}

type FileConfigLoader struct {
	Path string
}

// readDataFromFile reads data from file given to FileConfigLoader
func (f *FileConfigLoader) readDataFromFile() ([]byte, error) {
	return os.ReadFile(f.Path)
}

// unmarshalDataToConfig unmarshals []byte to ConfigFileData object.
func (f *FileConfigLoader) unmarshalDataToConfig(data []byte) (ConfigFileData, error) {
	var cfg ConfigFileData

	err := yaml.Unmarshal(data, &cfg)

	return cfg, err
}

func GetConfig(loader ConfigLoader) (*ConfigFileData, error) {
	var cfg ConfigFileData

	data, err := loader.readDataFromFile()
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg, err = loader.unmarshalDataToConfig(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return &cfg, nil
}
