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
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	defaultCalicoRegistry     = "docker.io"
	defaultEnterpriseRegistry = "gcr.io/unique-caldron-775/cnx"

	eeVersionsTpl = "enterprise.go.tpl"
	osVersionsTpl = "calico.go.tpl"
)

var (
	templateDir    = flag.String("template-dir", "hack/gen-versions/", "path to directory containing templates files named calico.go.tpl and enterprise.go.tpl")
	debug          = flag.Bool("debug", false, "enable debug logging")
	digests        = flag.Bool("digests", true, "get digests")
	eeVersionsPath = flag.String("ee-versions", "", "path to calico versions file")
	osVersionsPath = flag.String("os-versions", "", "path to enterprise versions file")
	gcrBearerFlag  = flag.String("gcr-bearer", "", "output of 'gcloud auth print-access-token")
)

func main() {
	flag.Parse()

	if *debug {
		log.SetOutput(os.Stderr)
		log.Println("debug logging enabled")
	}

	if *osVersionsPath != "" && *eeVersionsPath != "" {
		log.Println("must only set one of either -os-versions or -ee-versions")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *digests {
		if *gcrBearerFlag != "" {
			gcrBearer = *gcrBearerFlag
		} else {
			log.Print("no gcr bearer token passed. grabbing from current gcloud account...")
			gcrBearer = getGcrBearer()
			if gcrBearer == "" {
				log.Println("failed to get gcloud bearer token. Are you signed into gcloud cli?")
				os.Exit(1)
			}
		}
	}

	if *osVersionsPath != "" {
		if err := run(*osVersionsPath, filepath.Join(*templateDir, osVersionsTpl), defaultCalicoRegistry); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else if *eeVersionsPath != "" {
		if err := run(*eeVersionsPath, filepath.Join(*templateDir, eeVersionsTpl), defaultEnterpriseRegistry); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else {
		log.Println("must specify either -os-versions or -ee-versions")
		flag.PrintDefaults()
	}
}

func run(versionsPath, tpl, defaultRegistry string) error {
	vz, err := GetComponents(versionsPath)
	if err != nil {
		return err
	}

	if *digests {
		if err := updateDigests(vz, defaultRegistry); err != nil {
			return fmt.Errorf("failed to get digest for components: %v", err)
		}
	}

	return render(tpl, vz)
}

func getGcrBearer() string {
	t, err := exec.Command("gcloud", "auth", "print-access-token").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(t))
}
