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
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

const versionsGoPath = "pkg/components/versions.go"

func main() {
	eeVersionsPath := flag.String("ee-versions", "", "path to os versions file")
	osVersionsPath := flag.String("os-versions", "", "path to ee versions file")
	flag.Parse()

	if *osVersionsPath == "" || *eeVersionsPath == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := run(*osVersionsPath, *eeVersionsPath); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(versionsGoPath)
}

func run(osVersionsPath, eeVersionsPath string) error {
	osv, err := loadVersions(osVersionsPath)
	if err != nil {
		return fmt.Errorf("failed to load OS versions: %v", err)
	}

	eev, err := loadVersions(eeVersionsPath)
	if err != nil {
		return fmt.Errorf("failed to load EE versions: %v", err)
	}

	if err := writeVersions(osv, eev); err != nil {
		return fmt.Errorf("failed to write versions: %v", err)
	}

	return nil
}

type Components map[string]struct {
	Version string
}

func (c Components) get(component string) string {
	if comp, ok := c[component]; ok {
		return comp.Version
	}
	panic(fmt.Sprintf("couldn't find value for '%s'", component))
}

func loadVersions(versionsPath string) (Components, error) {
	var c struct {
		Components Components
	}

	f, err := ioutil.ReadFile(versionsPath)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(f, &c); err != nil {
		return nil, err
	}

	return c.Components, nil
}

func writeVersions(osVersions, eeVersions Components) error {
	f, err := os.Create(versionsGoPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	var ss = []string{
		"// This file is auto generated sometimes so if you are changing or updating",
		"// it then you should consider updating hack/gen-versions/main.go also.",
		"package components",
		"",
		"// This section contains images used when installing open-source Calico.",
		"const (",
		`	VersionCalicoNode            = "` + osVersions.get("calico/node") + `"`,
		`	VersionCalicoCNI             = "` + osVersions.get("calico/cni") + `"`,
		`	VersionCalicoTypha           = "` + osVersions.get("typha") + `"`,
		`	VersionCalicoKubeControllers = "` + osVersions.get("calico/kube-controllers") + `"`,
		`	VersionFlexVolume            = "` + osVersions.get("flexvol") + `"`,
		")",
		"",
		"// This section contains images used when installing Tigera Secure.",
		"const (",
		"	// Overrides for Calico.",
		`	VersionTigeraNode            = "` + eeVersions.get("cnx-node") + `"`,
		`	VersionTigeraTypha           = "` + eeVersions.get("typha") + `"`,
		`	VersionTigeraKubeControllers = "` + eeVersions.get("cnx-kube-controllers") + `"`,
		"",
		"	// API server images.",
		`	VersionAPIServer   = "` + eeVersions.get("cnx-apiserver") + `"`,
		`	VersionQueryServer = "` + eeVersions.get("cnx-queryserver") + `"`,
		"",
		"	// Logging",
		`	VersionFluentd = "` + eeVersions.get("fluentd") + `"`,
		"",
		"	// Compliance images",
		`	VersionComplianceController  = "` + eeVersions.get("compliance-controller") + `"`,
		`	VersionComplianceReporter    = "` + eeVersions.get("compliance-reporter") + `"`,
		`	VersionComplianceServer      = "` + eeVersions.get("compliance-server") + `"`,
		`	VersionComplianceSnapshotter = "` + eeVersions.get("compliance-snapshotter") + `"`,
		`	VersionComplianceBenchmarker = "` + eeVersions.get("compliance-benchmarker") + `"`,
		"",
		"	// Intrusion detection images.",
		`	VersionIntrusionDetectionController   = "` + eeVersions.get("intrusion-detection-controller") + `"`,
		`	VersionIntrusionDetectionJobInstaller = "` + eeVersions.get("elastic-tsee-installer") + `"`,
		"",
		"	// Manager images.",
		`	VersionManager = "` + eeVersions.get("cnx-manager") + `"`,
		`	VersionManagerProxy   = "` + eeVersions.get("voltron") + `"`,
		`	VersionManagerEsProxy = "` + eeVersions.get("es-proxy") + `"`,
		"",
		"	// ECK Elasticsearch images",
		`	VersionECKOperator = "` + eeVersions.get("elasticsearch-operator") + `"`,
		`	VersionECKElasticsearch = "` + eeVersions.get("elasticsearch") + `"`,
		`	VersionECKKibana = "` + eeVersions.get("eck-kibana") + `"`,
		`	VersionKibana = "` + eeVersions.get("kibana") + `"`,
		`	VersionEsCurator = "` + eeVersions.get("es-curator") + `"`,
		"",
		"	// Multicluster tunnel image.",
		`	VersionGuardian = "` + eeVersions.get("guardian") + `"`,
		")",
	}

	for _, s := range ss {
		if _, err := f.WriteString(s + "\n"); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}

	return nil
}
