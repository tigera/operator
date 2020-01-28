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
	"log"
	"os"
	"text/template"

	"gopkg.in/yaml.v2"
)

var (
	versionsGoTpl  = flag.String("versions-go-tpl", "hack/gen-versions/versions.go.tpl", "path to versions.go.tpl")
	debug          = flag.Bool("debug", false, "enable debug logging")
	eeVersionsPath = flag.String("ee-versions", "", "path to os versions file")
	osVersionsPath = flag.String("os-versions", "", "path to ee versions file")
)

func main() {
	flag.Parse()

	if *debug {
		log.SetOutput(os.Stderr)
		log.Println("debug logging enabled")
	}

	if *osVersionsPath == "" && *eeVersionsPath == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := run(*osVersionsPath, *eeVersionsPath); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func imageRef(r, i, v string) string {
	return fmt.Sprintf("%s/%s:%s", r, i, v)
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

type Versions struct {
	Calico, Enterprise Components
}

type Components map[string]Component

type Component struct {
	Version,
	Registry,
	Image string
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
	t, err := template.ParseFiles(*versionsGoTpl)
	if err != nil {
		return fmt.Errorf("failed to parse template file file: %v", err)
	}

	t.Option("missingkey=error")

	vz := Versions{Calico: osVersions, Enterprise: eeVersions}

	if err := t.Execute(os.Stdout, vz); err != nil {
		return err
	}

	return nil
}
