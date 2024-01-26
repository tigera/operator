// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"log"
	"os"
	"path/filepath"
)

const (
	defaultCalicoRegistry     = "docker.io"
	defaultEnterpriseRegistry = "gcr.io/unique-caldron-775/cnx"

	eeVersionsTpl     = "enterprise.go.tpl"
	osVersionsTpl     = "calico.go.tpl"
	commonVersionsTpl = "common.go.tpl"
)

var (
	templateDir        string
	debug              bool
	eeVersionsPath     string
	osVersionsPath     string
	commonVersionsPath string
	gcrBearer          string
)

func main() {
	flag.StringVar(&templateDir, "template-dir", "hack/gen-versions/", "path to directory containing templates files named calico.go.tpl and enterprise.go.tpl")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.StringVar(&eeVersionsPath, "ee-versions", "", "path to calico versions file")
	flag.StringVar(&osVersionsPath, "os-versions", "", "path to enterprise versions file")
	flag.StringVar(&commonVersionsPath, "common-versions", "", "path to common versions file")
	flag.StringVar(&gcrBearer, "gcr-bearer", "", "output of 'gcloud auth print-access-token")
	flag.Parse()

	if debug {
		log.SetOutput(os.Stderr)
		log.Println("debug logging enabled")
	}

	if osVersionsPath != "" && eeVersionsPath != "" {
		log.Println("must only set one of either -os-versions or -ee-versions")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if osVersionsPath != "" {
		if err := run(osVersionsPath, filepath.Join(templateDir, osVersionsTpl), defaultCalicoRegistry); err != nil {
			log.Fatalln(err)
		}
	} else if eeVersionsPath != "" {
		if err := run(eeVersionsPath, filepath.Join(templateDir, eeVersionsTpl), defaultEnterpriseRegistry); err != nil {
			log.Fatalln(err)
		}
	} else if commonVersionsPath != "" {
		if err := run(commonVersionsPath, filepath.Join(templateDir, commonVersionsTpl), defaultEnterpriseRegistry); err != nil {
			log.Fatalln(err)
		}
	} else {
		log.Println("must specify either -os-versions or -ee-versions")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func run(versionsPath, tpl, defaultRegistry string) error {
	vz, err := GetComponents(versionsPath)
	if err != nil {
		return err
	}

	return render(tpl, vz)
}
