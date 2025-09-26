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
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

// default images for components that do not specify an image in versions.yml
var (
	defaultImages = map[string]string{
		"calico/cni":                  "cni",
		"calico/cni-windows":          "cni-windows",
		"calico/dikastes":             "dikastes",
		"calico/kube-controllers":     "kube-controllers",
		"calico/node":                 "node",
		"calico/node-windows":         "node-windows",
		"calico/goldmane":             "goldmane",
		"calico/guardian":             "guardian",
		"calico/whisker":              "whisker",
		"calico/whisker-backend":      "whisker-backend",
		"calicoctl":                   "ctl",
		"flexvol":                     "pod2daemon-flexvol",
		"calico/csi":                  "csi",
		"csi-node-driver-registrar":   "node-driver-registrar",
		"typha":                       "typha",
		"key-cert-provisioner":        "key-cert-provisioner",
		"calico/apiserver":            "apiserver",
		"calico/envoy-gateway":        "envoy-gateway",
		"calico/envoy-proxy":          "envoy-proxy",
		"calico/envoy-ratelimit":      "envoy-ratelimit",
		"eck-elasticsearch":           "unused-image",
		"eck-elasticsearch-operator":  "unused-image",
		"eck-kibana":                  "unused-image",
		"coreos-prometheus":           "unused-image",
		"coreos-alertmanager":         "unused-image",
		"guardian":                    "guardian",
		"node":                        "node",
		"node-windows":                "node-windows",
		"tigera-cni":                  "cni",
		"tigera-cni-windows":          "cni-windows",
		"linseed":                     "linseed",
		"gateway-api-envoy-gateway":   "envoy-gateway",
		"gateway-api-envoy-proxy":     "envoy-proxy",
		"gateway-api-envoy-ratelimit": "envoy-ratelimit",
	}
)

var ignoredImages = map[string]struct{}{
	"calico":            {},
	"networking-calico": {},
	"calico-private":    {},
	"manager-proxy":     {},
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

	// Image is the image name without any image path (e.g. cni, api-server)
	Image string `json:"image"`
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

	// parse through the components listed in versions.yml to:
	// - add known default images to any components that are missing them.
	// - ignore any components that are not actually images.
	// - trim imagePath from image names.
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

		// Trim off the imagePath from the image name if a '/' exists.
		// If there is no '/', the image name is left unchanged.
		// TODO: Remove this logic once all versions.yml files have been updated to
		// only contain imageName without imagePath.
		imageParts := strings.SplitAfterN(component.Image, "/", 2)
		if len(imageParts) == 2 {
			component.Image = imageParts[1]
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
