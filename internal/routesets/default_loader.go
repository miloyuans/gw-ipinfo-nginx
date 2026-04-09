package routesets

import "gopkg.in/yaml.v3"

type defaultFile struct {
	Routes []string `yaml:"routes"`
}

func loadDefaultFile(path string) ([]string, error) {
	content, err := readExpandedFile(path)
	if err != nil {
		return nil, err
	}
	var file defaultFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, err
	}
	return file.Routes, nil
}
