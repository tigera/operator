// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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
	"os"
	"text/template"

	"gopkg.in/yaml.v2"
)

var defaultImages = map[string]string{
	"calico/cni":                 "calico/cni",
	"calico/cni-windows":         "calico/cni-windows",
	"calico/dikastes":            "calico/dikastes",
	"calico/kube-controllers":    "calico/kube-controllers",
	"calico/node":                "calico/node",
	"calico/node-windows":        "calico/node-windows",
	"calico/goldmane":            "calico/goldmane",
	"calicoctl":                  "calico/ctl",
	"flannel":                    "coreos/flannel",
	"flexvol":                    "calico/pod2daemon-flexvol",
	"calico/csi":                 "calico/csi",
	"csi-node-driver-registrar":  "calico/node-driver-registrar",
	"typha":                      "calico/typha",
	"key-cert-provisioner":       "calico/key-cert-provisioner",
	"eck-elasticsearch":          "unused/image",
	"eck-elasticsearch-operator": "unused/image",
	"eck-kibana":                 "unused/image",
	"coreos-prometheus":          "unused/image",
	"coreos-alertmanager":        "unused/image",
	"guardian":                   "tigera/guardian",
	"cnx-node":                   "tigera/cnx-node",
	"cnx-node-windows":           "tigera/cnx-node-windows",
	"tigera-cni":                 "tigera/cni",
	"tigera-cni-windows":         "tigera/cni-windows",
	"calico/apiserver":           "calico/apiserver",
	"tigera/linseed":             "tigera/linseed",
}

var ignoredImages = map[string]struct{}{
	"calico":            {},
	"networking-calico": {},
	"calico-private":    {},
	"cnx-manager-proxy": {},
	"busybox":           {},
	"calico/api":        {},
	"libcalico-go":      {},
}

type Release struct {
	// Title is the Release version and should match the major.minor.patch of the
	// Calico or Enterprise version included in the operator.
	Title      string     `json:"title"`
	Components Components `json:"components"`
}

type Components map[string]*Component

type Component struct {
	Version  string `json:"version"`
	Registry string `json:"registry"`
	Image    string `json:"image"`
}

// GetComponents parses a versions.yml file, scrubs the data of known issues,
// and returns the data in a Components struct.
func GetComponents(versionsPath string) (Release, error) {
	var cv Release
	v, err := readComponents(versionsPath)
	if err != nil {
		return cv, fmt.Errorf("failed to read components: %v", err)
	}

	cv.Components = make(Components)
	cv.Title = v.Title

	// add known default images to any components that are missing them.
	for key, component := range v.Components {
		if _, ignore := ignoredImages[key]; ignore {
			continue
		}

		if component.Image == "" {
			image := defaultImages[key]
			if image == "" {
				return cv, fmt.Errorf("no image nor default image available for component '%s'. "+
					"Either fill in the 'image' field or update this code with a defaultImage.", key)
			}
			component.Image = image
		}

		cv.Components[key] = component
	}

	return cv, nil
}

// readComponents opens a versions.yml file and returns a Release
func readComponents(versionsPath string) (Release, error) {
	var cr Release
	f, err := os.ReadFile(versionsPath)
	if err != nil {
		return cr, err
	}

	if err := yaml.Unmarshal(f, &cr); err != nil {
		return cr, err
	}

	return cr, nil
}

func render(tplFile string, vz Release) error {
	t, err := template.ParseFiles(tplFile)
	if err != nil {
		return fmt.Errorf("failed to parse template file file: %v", err)
	}
	t.Option("missingkey=error")

	return t.Execute(os.Stdout, vz)
}
