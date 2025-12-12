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
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

//go:embed templates/release-notes.md.gotmpl
var releaseNoteTemplate string

const (
	dockerHub    = "docker.io"
	quayRegistry = "quay.io"

	mainRepo         = "tigera/operator"
	defaultImageName = "tigera/operator"

	sourceGitHubURL = `https://github.com/` + mainRepo + `/raw/%s/%s`

	configDir        = "config"
	calicoConfig     = configDir + "/calico_versions.yml"
	enterpriseConfig = configDir + "/enterprise_versions.yml"

	releaseFormat           = `^v\d+\.\d+\.\d+$`
	enterpriseReleaseFormat = `^v\d+\.\d+\.\d+(-\d+\.\d+)?$`
	hashreleaseFormat       = `^v\d+\.\d+\.\d+-%s-\d+-g[a-f0-9]{12}-[a-z0-9-]+$`
	baseVersionFormat       = `^v\d+\.\d+\.\d+(-%s-\d+-g[a-f0-9]{12}-[a-z0-9-]+)?$`
)

// Context keys
const (
	githubOrgCtxKey  contextKey = "github-org"
	githubRepoCtxKey contextKey = "github-repo"
	versionCtxKey    contextKey = "version"
	headBranchCtxKey contextKey = "head-branch"
)

type contextKey string

type Component struct {
	Version string `yaml:"version"`
	Image   string `yaml:"image,omitempty"`
}

type CalicoVersion struct {
	Title      string               `yaml:"title"`
	Components map[string]Component `yaml:"components"`
}

func gitVersion() (string, error) {
	return git("describe", "--tags", "--always", "--long", "--abbrev=12", "--dirty")
}

func gitDir() (string, error) {
	return git("rev-parse", "--show-toplevel")
}

func git(args ...string) (string, error) {
	return runCommand("git", args, nil)
}

func gitInDir(dir string, args ...string) (string, error) {
	return runCommandInDir(dir, "git", args, nil)
}

func makeInDir(dir string, targets string, env ...string) (string, error) {
	return runCommandInDir(dir, "make", strings.Fields(targets), env)
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

func addRepoInfoToCtx(ctx context.Context, repo string) (context.Context, error) {
	if ctx.Value(githubOrgCtxKey) != nil && ctx.Value(githubRepoCtxKey) != nil {
		return ctx, nil
	}
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return ctx, fmt.Errorf("invalid repo format, expected 'org/repo', got: %s", repo)
	}
	ctx = context.WithValue(ctx, githubOrgCtxKey, parts[0])
	ctx = context.WithValue(ctx, githubRepoCtxKey, parts[1])
	return ctx, nil
}

func calicoConfigVersions(dir, filePath string) (CalicoVersion, error) {
	fullPath := fmt.Sprintf("%s/%s", dir, filePath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return CalicoVersion{}, fmt.Errorf("error reading version file %s: %w", fullPath, err)
	}
	var version CalicoVersion
	if err := yaml.Unmarshal(data, &version); err != nil {
		return CalicoVersion{}, fmt.Errorf("error unmarshaling version file %s: %w", fullPath, err)
	}
	return version, nil
}

// Retrieves the Calico and Calico Enterprise versions included in this release.
func calicoVersions(rootDir, operatorVersion string, local bool) (map[string]string, error) {
	versions := make(map[string]string)

	if local && rootDir == "" {
		return versions, fmt.Errorf("rootDir must be specified when using local flag")
	} else if !local {
		rootDir = filepath.Join(os.TempDir(), fmt.Sprintf("operator-%s", operatorVersion))
		err := os.MkdirAll(filepath.Join(rootDir, configDir), os.ModePerm)
		if err != nil {
			return versions, fmt.Errorf("error creating config directory: %s", err)
		}
		defer func() {
			_ = os.RemoveAll(rootDir)
		}()
		if err := retrieveBaseVersionConfig(operatorVersion, rootDir); err != nil {
			return versions, fmt.Errorf("error retrieving version config: %s", err)
		}
	}

	calicoVer, err := calicoConfigVersions(rootDir, calicoConfig)
	if err != nil {
		return versions, fmt.Errorf("error retrieving Calico version: %s", err)
	}
	if isReleaseVersion, err := isReleaseVersionFormat(calicoVer.Title); err == nil && isReleaseVersion {
		versions["Calico"] = calicoVer.Title
	} else {
		return versions, fmt.Errorf("the Calico version specified (%s) is not a valid release version: %w", calicoVer.Title, err)
	}
	enterpriseVer, err := calicoConfigVersions(rootDir, enterpriseConfig)
	if err != nil {
		return versions, fmt.Errorf("error retrieving Enterprise version: %s", err)
	}
	if isReleaseVersion, err := isEnterpriseReleaseVersionFormat(enterpriseVer.Title); err == nil && isReleaseVersion {
		versions["Calico Enterprise"] = enterpriseVer.Title
	}
	return versions, nil
}

// isReleaseVersionFormat checks if the version in the format vX.Y.Z.
func isReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(releaseFormat)
	if err != nil {
		return false, fmt.Errorf("error compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

// isEnterpriseReleaseVersionFormat checks if the version is in the format vX.Y.Z or vX.Y.Z-A.B.
func isEnterpriseReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(enterpriseReleaseFormat)
	if err != nil {
		return false, fmt.Errorf("error compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

// Check if the Enterprise version is a prerelease.
// First, it checks if the version matches the release format.
// If it does, it then checks if there is a prerelease segment in the version.
func isPrereleaseEnterpriseVersion(rootDir string) (bool, error) {
	enterpriseVer, err := calicoConfigVersions(rootDir, enterpriseConfig)
	if err != nil {
		return false, fmt.Errorf("retrieving Enterprise version: %s", err)
	}
	release, err := isEnterpriseReleaseVersionFormat(enterpriseVer.Title)
	if err != nil {
		return false, fmt.Errorf("checking Enterprise version format: %s", err)
	}
	if !release {
		return false, nil
	}
	ver, err := semver.NewVersion(enterpriseVer.Title)
	if err != nil {
		return false, fmt.Errorf("parsing Enterprise version (%s): %s", enterpriseVer.Title, err)
	}
	return ver.Prerelease() != "", nil
}

// Ensure string ends with a slash, if empty string returns empty string.
func addTrailingSlash(registry string) string {
	if registry == "" {
		return ""
	}
	if strings.HasSuffix(registry, "/") {
		return registry
	}
	return registry + "/"
}
