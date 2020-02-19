package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"text/template"

	"gopkg.in/yaml.v2"
)

var defaultImages = map[string]string{
	"calico/cni":              "calico/cni",
	"calico/dikastes":         "calico/dikastes",
	"calico/kube-controllers": "calico/kube-controllers",
	"calico/node":             "calico/node",
	"calicoctl":               "calico/ctl",
	"flannel":                 "coreos/flannel",
	"flexvol":                 "calico/pod2daemon-flexvol",
	"typha":                   "calico/typha",
	"eck-kibana":              "tigera/kibana",
}

type Components map[string]*Component

type Component struct {
	Version  string `json:"version"`
	Registry string `json:"registry"`
	Digest   string `json:"digest"`
	Image    string `json:"image"`
}

// GetComponents parses a versions.yml file, scrubs the data of known issues,
// and returns the data in a Components struct.
func GetComponents(versionsPath string) (Components, error) {
	v, err := readComponents(versionsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read components: %v", err)
	}

	comps := make(Components)

	// add known default images to any components that are missing them.
	for key, component := range v {
		if key == "calico" || key == "networking-calico" {
			continue
		}

		if component.Image == "" {
			image := defaultImages[key]
			if image == "" {
				return nil, fmt.Errorf("no image nor default image available for component '%s'. "+
					"Either fill in the 'image' field or update this code with a defaultImage.", key)
			}
			component.Image = image
		}

		comps[key] = component
	}

	return comps, nil
}

// readComponents opens a versions.yml file and returns the components
// section in a Components struct.
func readComponents(versionsPath string) (Components, error) {
	f, err := ioutil.ReadFile(versionsPath)
	if err != nil {
		return nil, err
	}
	c := make(map[string]Components)
	if err := yaml.Unmarshal(f, &c); err != nil {
		return nil, err
	}

	return c["components"], nil
}

func render(tplFile string, vz Components) error {
	t, err := template.ParseFiles(tplFile)
	if err != nil {
		return fmt.Errorf("failed to parse template file file: %v", err)
	}
	t.Option("missingkey=error")

	return t.Execute(os.Stdout, vz)
}
