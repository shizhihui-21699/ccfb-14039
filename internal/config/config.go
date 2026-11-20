// Package config loads the service configuration: the static routing facts
// (registry) and the detector's tunable thresholds.
package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"routewatch/internal/detect"
	"routewatch/internal/registry"
)

// File is the on-disk shape of config/*.yaml.
type File struct {
	Registry registry.Registry `yaml:"registry"`
	Detector detect.Config     `yaml:"detector"`
}

// Load reads and validates a config file.
func Load(path string) (*registry.Registry, detect.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, detect.Config{}, fmt.Errorf("read config: %w", err)
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, detect.Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := f.Registry.Load(); err != nil {
		return nil, detect.Config{}, fmt.Errorf("%s: %w", path, err)
	}
	cfg := f.Detector
	if err := cfg.Validate(); err != nil {
		return nil, detect.Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return &f.Registry, cfg, nil
}

// LoadRegistry loads only the registry section, for the simulator and the
// generator which do not need detector thresholds.
func LoadRegistry(path string) (*registry.Registry, error) {
	reg, _, err := Load(path)
	return reg, err
}
