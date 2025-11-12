// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	dockerHub    = "docker.io"
	quayRegistry = "quay.io"

	defaultImageName = "tigera/operator"

	sourceGitHubURL = `https://github.com/tigera/operator/raw/%s/%s`

	calicoConfig     = "config/calico_versions.yml"
	enterpriseConfig = "config/enterprise_versions.yml"

	releaseFormat     = `^v\d+\.\d+\.\d+$`
	hashreleaseFormat = `^v\d+\.\d+\.\d+-%s-\d+-g[a-f0-9]{12}-[a-z0-9-]+$`
	baseVersionFormat = `^v\d+\.\d+\.\d+(-%s-\d+-g[a-f0-9]{12}-[a-z0-9-]+)?$`
)

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func gitVersion() (string, error) {
	return runCommand("git", []string{"describe", "--tags", "--always", "--long", "--abbrev=12", "--dirty"}, nil)
}

func runCommand(name string, args, env []string) (string, error) {
	return runCommandInDir("", name, args, env)
}

func runCommandInDir(dir, name string, args, env []string) (string, error) {
	cmd := exec.Command(name, args...)
	if len(env) != 0 {
		cmd.Env = env
	}
	cmd.Dir = dir
	var outb, errb bytes.Buffer
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		// If debug level is enabled, also write to stdout.
		cmd.Stdout = io.MultiWriter(os.Stdout, &outb)
		cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
	} else {
		// Otherwise, just capture the output to return.
		cmd.Stdout = io.MultiWriter(&outb)
		cmd.Stderr = io.MultiWriter(&errb)
	}
	logrus.WithFields(logrus.Fields{
		"cmd": cmd.String(),
		"dir": dir,
	}).Debugf("Running %s command", name)
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(outb.String()), err
}
