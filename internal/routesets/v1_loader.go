package routesets

import "gopkg.in/yaml.v3"

type passRouteFile struct {
	Routes []passRoute `yaml:"routes"`
}

type passRoute struct {
	ID     string      `yaml:"id"`
	Source passSource  `yaml:"source"`
	Target passTarget  `yaml:"target"`
}

type passSource struct {
	Host       string `yaml:"host"`
	PathPrefix string `yaml:"path_prefix"`
}

type passTarget struct {
	PublicURL      string `yaml:"public_url"`
	BackendService string `yaml:"backend_service"`
	BackendHost    string `yaml:"backend_host"`
}

func loadV1File(path string) ([]passRoute, error) {
	content, err := readExpandedFile(path)
	if err != nil {
		return nil, err
	}
	var file passRouteFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, err
	}
	return file.Routes, nil
}
