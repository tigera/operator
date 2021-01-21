// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"eck-elasticsearch":       "tigera/elasticsearch",
	"eck-kibana":              "tigera/kibana",
	"guardian":                "tigera/guardian",
	"tigera-cni":              "tigera/cni",
	"rdtigera/init-container": "rdtigera/init-container",
}

type Components map[string]*Component

type Component struct {
	Version  string `json:"version"`
	Registry string `json:"registry"`
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
		if key == "calico" || key == "networking-calico" || key == "calico-private" || key == "cnx-manager-proxy" || key == "busybox" {
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

	c := struct {
		Components Components
	}{}
	if err := yaml.Unmarshal(f, &c); err != nil {
		return nil, err
	}

	return c.Components, nil
}

func render(tplFile string, vz Components) error {
	t, err := template.ParseFiles(tplFile)
	if err != nil {
		return fmt.Errorf("failed to parse template file file: %v", err)
	}
	t.Option("missingkey=error")

	return t.Execute(os.Stdout, vz)
}
