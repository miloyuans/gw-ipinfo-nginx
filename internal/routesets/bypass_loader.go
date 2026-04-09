package routesets

import "gopkg.in/yaml.v3"

type bypassRouteFile struct {
	Routes []bypassRoute `yaml:"routes"`
}

type bypassRoute struct {
	ID      string        `yaml:"id"`
	Source  passSource    `yaml:"source"`
	Backend bypassBackend `yaml:"backend"`
}

type bypassBackend struct {
	Service string `yaml:"service"`
	Host    string `yaml:"host"`
}

func loadBypassFile(path string) ([]bypassRoute, error) {
	content, err := readExpandedFile(path)
	if err != nil {
		return nil, err
	}
	var file bypassRouteFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, err
	}
	return file.Routes, nil
}
