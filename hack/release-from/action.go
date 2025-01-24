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
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

// releaseFrom is the main action for the command.
// It builds (and publishes) a new operator based on the base version specified.
func releaseFrom(ctx context.Context, c *cli.Command) error {
	// get root directory of operator git repo
	repoRootDir, err := runCommand("git", []string{"rev-parse", "--show-toplevel"}, nil)
	if err != nil {
		return fmt.Errorf("error getting git root directory: %s", err)
	}

	// fetch config from the base version of the operator
	if err := retrieveBaseVersionConfig(c.String(baseOperatorFlag.Name), repoRootDir); err != nil {
		return fmt.Errorf("error getting base version config: %s", err)
	}

	// Apply new version overrides
	calicoOverrides := c.StringSlice(exceptCalicoFlag.Name)
	if len(calicoOverrides) > 0 {
		if err := modifyComponentConfig(repoRootDir, calicoConfig, calicoOverrides); err != nil {
			return fmt.Errorf("error overriding calico config: %s", err)
		}
	}
	enterpriseOverrides := c.StringSlice(exceptEnterpriseFlag.Name)
	if len(enterpriseOverrides) > 0 {
		if err := modifyComponentConfig(repoRootDir, enterpriseConfig, enterpriseOverrides); err != nil {
			return fmt.Errorf("error overriding calico config: %s", err)
		}
	}

	// Build either a new release or a new hashrelease operator
	version := c.String(versionFlag.Name)
	isReleaseVersion, err := isReleaseVersionFormat(version)
	if err != nil {
		return fmt.Errorf("error determining if version is a release: %s", err)
	} else if isReleaseVersion {
		return newOperator(repoRootDir, version, c.String(gitRemoteFlag.Name), c.Bool(publishFlag.Name))
	}

	return newHashreleaseOperator(repoRootDir, version, c.String(imageFlag.Name), c.String(registryFlag.Name), c.StringSlice(archFlag.Name), c.Bool(publishFlag.Name))
}

// isReleaseVersionFormat checks if the version in the format vX.Y.Z.
func isReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(releaseFormat)
	if err != nil {
		return false, fmt.Errorf("error compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

// newOperator handles creating a new operator release.
// If publish is true, it will push a new tag to the git remote to trigger a release.
// Otherwise, it will only commit the changes to the git repo locally.
func newOperator(dir, version, remote string, publish bool) error {
	if _, err := runCommandInDir(dir, "git", []string{"add", "config/"}, nil); err != nil {
		return fmt.Errorf("error adding changes in git: %s", err)
	}
	if _, err := runCommandInDir(dir, "git", []string{"commit", "-m", fmt.Sprintf("Release %s", version)}, nil); err != nil {
		return fmt.Errorf("error committing changes in git: %s", err)
	}
	if _, err := runCommandInDir(dir, "git", []string{"tag", version}, nil); err != nil {
		return fmt.Errorf("error tagging release in git: %s", err)
	}
	if !publish {
		logrus.Info("skip pushing tag to git for publishing release")
		return nil
	}
	if _, err := runCommandInDir(dir, "git", []string{"push", remote, version}, nil); err != nil {
		return fmt.Errorf("error pushing tag in git: %s", err)
	}
	logrus.Warn("Ensure that the changes are merged into the main branch as well.")
	logrus.Info("Follow the release progress in CI.")
	return nil
}

// newHashreleaseOperator creates a new operator for a hashrelease.
// if publish is true, it will also publish the operator to registry.
func newHashreleaseOperator(dir, version, imageName, registry string, arches []string, publish bool) error {
	defer func() {
		if _, err := runCommandInDir(dir, "git", []string{"checkout", "config/"}, nil); err != nil {
			logrus.WithError(err).Error("error reverting changes in config/")
		}
	}()
	if err := buildHashreleaseOperator(dir, version, imageName, registry, arches); err != nil {
		return fmt.Errorf("error building operator: %s", err)
	}
	if !publish {
		logrus.Info("skip publishing images to registry")
		return nil
	}
	return publishHashreleaseOperator(version, imageName, registry, arches)
}

func buildHashreleaseOperator(dir, version, imageName, registry string, arches []string) error {
	initImageName := fmt.Sprintf("%s-init", imageName)
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", imageName))
	if _, err := runCommandInDir(dir, "make", []string{"image-all"}, env); err != nil {
		return err
	}
	for _, arch := range arches {
		tag := fmt.Sprintf("%s/%s:%s-%s", registry, imageName, version, arch)
		if _, err := runCommand("docker", []string{
			"tag",
			fmt.Sprintf("%s:latest-%s", imageName, arch),
			tag,
		}, env); err != nil {
			return err
		}
		logrus.WithField("tag", tag).Debug("Built image")
	}

	env = os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", imageName))
	env = append(env, fmt.Sprintf("BUILD_INIT_IMAGE=%s", initImageName))
	if _, err := runCommandInDir(dir, "make", []string{"image-init"}, env); err != nil {
		return err
	}

	initTag := fmt.Sprintf("%s/%s:%s", registry, initImageName, version)
	if _, err := runCommand("docker", []string{
		"tag",
		fmt.Sprintf("%s:latest", initImageName),
		fmt.Sprintf("%s/%s:%s", registry, initImageName, version),
	}, env); err != nil {
		return err
	}
	logrus.WithField("tag", initTag).Debug("Built init image")
	return nil
}

// publishHashreleaseOperator publishes the hashrelease operator to registry.
func publishHashreleaseOperator(version, imageName, registry string, archs []string) error {
	multiArchTags := []string{}
	for _, arch := range archs {
		tag := fmt.Sprintf("%s/%s:%s-%s", registry, imageName, version, arch)
		if _, err := runCommand("docker", []string{"push", tag}, nil); err != nil {
			return err
		}
		logrus.WithField("tag", tag).Debug("Pushed image")
		multiArchTags = append(multiArchTags, tag)
	}
	image := fmt.Sprintf("%s/%s:%s", registry, imageName, version)
	cmd := []string{"manifest", "create", image}
	for _, tag := range multiArchTags {
		cmd = append(cmd, "--amend", tag)
	}
	if _, err := runCommand("docker", cmd, nil); err != nil {
		return err
	}
	if _, err := runCommand("docker", []string{"manifest", "push", "--purge", image}, nil); err != nil {
		return err
	}
	logrus.WithField("image", image).Debug("Pushed manifest")

	initImage := fmt.Sprintf("%s/%s-init:%s", registry, imageName, version)
	if _, err := runCommand("docker", []string{"push", initImage}, nil); err != nil {
		return err
	}
	logrus.WithField("image", initImage).Debug("Pushed init image")
	return nil
}

// modifyComponentConfig updates the version of image(s) specified in the selected config file
func modifyComponentConfig(repoRootDir, configFile string, updates []string) error {
	// open file locally
	localFilePath := fmt.Sprintf("%s/%s", repoRootDir, configFile)
	var root yaml.Node
	if data, err := os.ReadFile(localFilePath); err != nil {
		return fmt.Errorf("error reading local file %s: %s", configFile, err)
	} else if err = yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("error unmarshalling local file %s: %s", configFile, err)
	}

	for _, override := range updates {
		parts := strings.Split(override, ":")
		component := parts[0]
		version := parts[1]
		if err := updateComponentVersion(&root, []string{"components", component, "version"}, version); err != nil {
			return fmt.Errorf("error updating component %s to %s: %s", component, version, err)
		}
	}

	// overwrite local file with updated config
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return fmt.Errorf("error encoding updated config: %s", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("error closing encoder: %s", err)
	}
	if err := os.WriteFile(localFilePath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("error overwriting local file %s: %s", configFile, err)
	}
	return nil
}

// updateComponentVersion traverses the yaml node to update the version of the component.
func updateComponentVersion(node *yaml.Node, path []string, version string) error {
	current := node.Content[0]
	for i, key := range path {
		found := false
		for j := 0; j < len(current.Content)-1; j += 2 {
			keyNode := current.Content[j]
			valueNode := current.Content[j+1]

			logrus.WithFields(logrus.Fields{
				"key":   keyNode.Value,
				"value": valueNode.Value,
			}).Debug("Checking key and value")

			if keyNode.Value == key {
				if i == len(path)-1 {
					valueNode.Value = version
					return nil
				}

				if valueNode.Kind == yaml.MappingNode {
					current = valueNode
					found = true
					break
				} else {
					return fmt.Errorf("expected mapping node at path %v, got %v", path[:i+1], valueNode.Kind)
				}
			}
		}

		if !found {
			return fmt.Errorf("key '%s' not found at path %v", key, path[:i+1])
		}
	}
	return nil
}

// retrieveBaseVersionConfig gets the config to use as a base for the new operator
// from the base version of the operator.
func retrieveBaseVersionConfig(baseVersion, repoRootDir string) error {
	gitHashOrTag, err := extractGitHashOrTag(baseVersion)
	if err != nil {
		return fmt.Errorf("error extracting git hash or tag from %q: %s", baseVersion, err)
	}

	for _, configFilePath := range []string{calicoConfig, enterpriseConfig} {
		localFilePath := fmt.Sprintf("%s/%s", repoRootDir, configFilePath)
		url := fmt.Sprintf(sourceGitHubURL, gitHashOrTag, configFilePath)
		logrus.WithFields(logrus.Fields{
			"file":         configFilePath,
			"localPath":    localFilePath,
			"downloadPath": url,
		}).Debug("Replacing local file with downloaded file")

		if _, err := runCommand("curl", []string{"-L", "-o", localFilePath, url}, nil); err != nil {
			return fmt.Errorf("error downloading %s from %s: %s", configFilePath, url, err)
		}
	}
	return nil
}

// extractGitHashOrTag returns the tag for a release version
// or the git hash for a hashrelease version from the baseVersion.
func extractGitHashOrTag(baseVersion string) (string, error) {
	isReleaseVersion, err := isReleaseVersionFormat(baseVersion)
	if err != nil {
		return "", fmt.Errorf("error determining if version is a release: %s", err)
	}
	if isReleaseVersion {
		return baseVersion, nil
	}
	gitHashRegex, err := regexp.Compile(`g([0-9a-f]{12})`)
	if err != nil {
		return "", fmt.Errorf("error compiling git hash regex: %s", err)
	}
	matches := gitHashRegex.FindStringSubmatch(baseVersion)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("error finding git hash in base version")
}
