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
	"strings"
)

const (
	defaultCalicoRegistry     = "quay.io"
	defaultEnterpriseRegistry = "gcr.io/unique-caldron-775/cnx"
)

var (
	versionsGoTpl  = flag.String("versions-go-tpl", "hack/gen-versions/versions.go.tpl", "path to versions.go.tpl")
	debug          = flag.Bool("debug", false, "enable debug logging")
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

	if *osVersionsPath == "" && *eeVersionsPath == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *gcrBearerFlag != "" {
		gcrBearer = *gcrBearerFlag
	} else {
		log.Print("no gcr bearer token passed. grabbing from current gcloud account...")
		gcrBearer = getGcrBearer()
		if gcrBearer == "" {
			fmt.Println("failed to get gcloud bearer token. Are you signed into gcloud cli?")
			os.Exit(1)
		}
	}

	// get modified with digests
	osv, eev, err := getComponentHashes(*osVersionsPath, *eeVersionsPath)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// print them
	if err := printVersionsGo(*versionsGoTpl, osv, eev); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func getGcrBearer() string {
	t, err := exec.Command("gcloud", "auth", "print-access-token").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(t))
}
