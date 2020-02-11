package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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

// getComponentHashes traverses each entry in
func getComponentHashes(osVersionsPath, eeVersionsPath string) (Components, Components, error) {
	osv, err := readComponents(osVersionsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load OS versions: %v", err)
	}

	// make some adjustments to versions.yml.
	// networking-calico isn't associated with any real image so remove it
	delete(osv, "networking-calico")

	// add known default images to any components that are missing them.
	for key, component := range osv {
		if component.Image == "" {
			image := defaultImages[key]
			if image == "" {
				return nil, nil, fmt.Errorf("no image or default image available for component '%s'. "+
					"Either fill in the 'image' field or update this code with a defaultImage.", key)
			}
			osv[key].Image = image
		}
	}

	if err := updateDigests(osv, defaultCalicoRegistry); err != nil {
		return nil, nil, fmt.Errorf("failed to get digest for os components: %v", err)
	}

	if *debug {
		bits, _ := json.Marshal(osv)
		log.Println(string(bits))
	}

	eev, err := readComponents(eeVersionsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load EE versions: %v", err)
	}

	// add known default images to any components that are missing them.
	for key, component := range eev {
		if component.Image == "" {
			image := defaultImages[key]
			if image == "" {
				return nil, nil, fmt.Errorf("no image or default image available for key %s", key)
			}
			eev[key].Image = image
		}
	}
	delete(eev, "calico")
	delete(eev, "networking-calico")

	if err := updateDigests(eev, defaultEnterpriseRegistry); err != nil {
		return nil, nil, fmt.Errorf("failed to get digest for os components: %v", err)
	}

	return osv, eev, nil
}

// readComponents opens a versions.yml file and returns the components
// section in a Components struct.
func readComponents(versionsPath string) (Components, error) {
	f, err := ioutil.ReadFile(versionsPath)
	if err != nil {
		return nil, err
	}
	var c = map[string]Components{}
	if err := yaml.Unmarshal(f, &c); err != nil {
		return nil, err
	}

	return c["components"], nil
}

func printVersionsGo(tplFile string, osVersions, eeVersions Components) error {
	t, err := template.ParseFiles(tplFile)
	if err != nil {
		return fmt.Errorf("failed to parse template file file: %v", err)
	}
	t.Option("missingkey=error")

	var vz = map[string]Components{
		"Calico":     osVersions,
		"Enterprise": eeVersions,
	}

	return t.Execute(os.Stdout, vz)
}
