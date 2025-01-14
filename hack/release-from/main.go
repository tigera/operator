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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v2"
)

type component struct {
	Image    string `yaml:"image"`
	Version  string `yaml:"version"`
	Registry string `yaml:"registry"`
}

type productConfig struct {
	Title      string               `yaml:"title"`
	Components map[string]component `yaml:"components"`
}

func main() {
	cmd := &cli.Command{
		Name:  "operator-from",
		Usage: "CLI tool for releasing operator using a previous release",
		Flags: []cli.Flag{
			baseOperatorFlag,
			versionFlag,
			exceptCalicoFlag,
			exceptEnterpriseFlag,
			debugFlag,
		},
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			if c.Bool(debugFlag.Name) {
				logrus.SetLevel(logrus.DebugLevel)
			}
			// check if git repo is dirty
			if version, err := gitVersion(); err != nil {
				return ctx, fmt.Errorf("Error getting git version: %s", err)
			} else if strings.Contains(version, "dirty") {
				return ctx, fmt.Errorf("Git repo is dirty, please commit changes before releasing")
			}
			return ctx, nil
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			// get root directory of operator git repo
			repoRootDir, err := runCommand("git", []string{"rev-parse", "--show-toplevel"}, nil)
			if err != nil {
				return fmt.Errorf("Error getting git root directory: %s", err)
			}

			// fetch config from the base version of the operator
			if err := retrieveBaseVersionConfig(baseOperatorFlag.Name, repoRootDir); err != nil {
				return fmt.Errorf("Error getting base version config: %s", err)
			}

			// Apply new version overrides
			calicoOverrides := c.StringSlice(exceptCalicoFlag.Name)
			if len(calicoOverrides) > 0 {
				if err := overrideConfig(repoRootDir, calicoConfig, calicoOverrides); err != nil {
					return fmt.Errorf("Error overriding calico config: %s", err)
				}
			}
			enterpriseOverrides := c.StringSlice(exceptEnterpriseFlag.Name)
			if len(enterpriseOverrides) > 0 {
				if err := overrideConfig(repoRootDir, enterpriseConfig, enterpriseOverrides); err != nil {
					return fmt.Errorf("Error overriding calico config: %s", err)
				}
			}

			// Either build a new release or a new hashrelease operator
			version := c.String(versionFlag.Name)
			release, err := isRelease(version)
			if err != nil {
				return fmt.Errorf("Error determining if version is a release: %s", err)
			} else if release {
				return newOperator(repoRootDir, version, c.String(remoteFlag.Name))
			}

			return newHashreleaseOperator(repoRootDir, version, c.StringSlice(archFlag.Name))
		},
	}
	// Run the app.
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logrus.WithError(err).Fatal("Error building new operator")
	}
}

func isRelease(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(releaseFormat)
	if err != nil {
		return false, fmt.Errorf("Error compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

func newOperator(dir, version, remote string) error {
	// TODO: Commit, tag and push changes
	if _, err := runCommandInDir(dir, "git", []string{"add", "config/"}, nil); err != nil {
		return fmt.Errorf("Error adding changes in git: %s", err)
	}
	if _, err := runCommandInDir(dir, "git", []string{"commit", "-m", fmt.Sprintf("Release %s", version)}, nil); err != nil {
		return fmt.Errorf("Error committing changes in git: %s", err)
	}
	if _, err := runCommandInDir(dir, "git", []string{"tag", version}, nil); err != nil {
		return fmt.Errorf("Error tagging release in git: %s", err)
	}
	if _, err := runCommandInDir(dir, "git", []string{"push", remote, version}, nil); err != nil {
		return fmt.Errorf("Error pushing tag in git: %s", err)
	}
	return nil
}

func newHashreleaseOperator(dir, version string, archs []string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(archs, " ")))
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", version))
	if _, err := runCommandInDir(dir, "make", []string{"image-all"}, env); err != nil {
		return err
	}
	for _, arch := range archs {
		tag := fmt.Sprintf("%s/%s:%s-%s", quayRegistry, imageName, version, arch)
		if _, err := runCommand("docker", []string{
			"tag",
			fmt.Sprintf("%s:latest-%s", imageName, arch),
			tag,
		}, env); err != nil {
			return err
		}
		logrus.WithField("tag", tag).Debug("Built image")
	}

	initTag := fmt.Sprintf("%s/%s-init:%s", quayRegistry, imageName, version)
	if _, err := runCommand("docker", []string{
		"tag",
		fmt.Sprintf("%s-init:latest", imageName),
		fmt.Sprintf("%s/%s-init:%s", quayRegistry, imageName, version),
	}, env); err != nil {
		return err
	}
	logrus.WithField("tag", initTag).Debug("Built init image")
	return publishHashreleaseOperator(version, archs)
}

func publishHashreleaseOperator(version string, archs []string) error {
	multiArchTags := []string{}
	for _, arch := range archs {
		tag := fmt.Sprintf("%s/%s:%s-%s", quayRegistry, imageName, version, arch)
		if _, err := runCommand("docker", []string{"push", tag}, nil); err != nil {
			return err
		}
		logrus.WithField("tag", tag).Debug("Pushed image")
		multiArchTags = append(multiArchTags, tag)
	}
	image := fmt.Sprintf("%s/%s:%s", quayRegistry, imageName, version)
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

	initImage := fmt.Sprintf("%s/%s-init:%s", quayRegistry, imageName, version)
	if _, err := runCommand("docker", []string{"push", initImage}, nil); err != nil {
		return err
	}
	logrus.WithField("image", initImage).Debug("Pushed init image")
	return nil
}

func overrideConfig(repoRootDir, configFile string, overrides []string) error {
	components := make(map[string]string)
	for _, override := range overrides {
		parts := strings.Split(override, ":")
		if len(parts) != 2 {
			return fmt.Errorf("Invalid override: %s", override)
		}
		components[parts[0]] = parts[1]
	}
	// open file locally
	localFile := fmt.Sprintf("%s/%s", repoRootDir, configFile)
	var config productConfig
	if data, err := os.ReadFile(localFile); err != nil {
		return fmt.Errorf("Error reading local file %s: %s", configFile, err)
	} else if err = yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("Error unmarshalling local file %s: %s", configFile, err)
	}
	for c, ver := range components {
		if _, ok := config.Components[c]; ok {
			config.Components[c] = component{
				Image:    config.Components[c].Image,
				Version:  ver,
				Registry: config.Components[c].Registry,
			}
		}
	}
	// overwrite local file with updated config
	if err := os.WriteFile(localFile, []byte(fmt.Sprintf("%s\n", config)), 0o644); err != nil {
		return fmt.Errorf("Error overwriting local file %s: %s", configFile, err)
	}
	return nil
}

func retrieveBaseVersionConfig(baseVersion, repoRootDir string) error {
	url, err := getDownloadURL(baseVersion)
	if err != nil {
		return fmt.Errorf("Error getting download URL: %s", err)
	}

	for _, file := range []string{calicoConfig, enterpriseConfig} {
		// open file locally
		localFile := fmt.Sprintf("%s/%s", repoRootDir, file)
		out, err := os.OpenFile(localFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("Error opening local file %s: %s", file, err)
		}
		defer out.Close()

		// download file from base version
		resp, err := http.Get(fmt.Sprintf("%s/%s", url, file))
		if err != nil {
			return fmt.Errorf("Error downloading %s: %s", file, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Error downloading %s: %s", file, resp.Status)
		}

		// overwrite local file with downloaded file
		if _, err = io.Copy(out, resp.Body); err != nil {
			return fmt.Errorf("Error overwriting local file %s: %s", localFile, err)
		}
		logrus.WithFields(logrus.Fields{
			"file":         file,
			"localPath":    localFile,
			"downloadPath": url,
		}).Debug("Overwrote local file with downloaded file")
	}
	return nil
}

func getDownloadURL(baseVersion string) (string, error) {
	release, err := isRelease(baseVersion)
	if err != nil {
		return "", fmt.Errorf("Error determining if version is a release: %s", err)
	}
	if release {
		return fmt.Sprintf("%s/refs/tags/%s", baseDownloadURL, baseVersion), nil
	}
	gitHashRegex, err := regexp.Compile(`^g([a-f0-9]{12})`)
	if err != nil {
		return "", fmt.Errorf("Error compiling git hash regex: %s", err)
	}
	matches := gitHashRegex.FindStringSubmatch(baseVersion)
	if len(matches) < 1 {
		return "", fmt.Errorf("Error finding git hash in base version")
	}
	return fmt.Sprintf("%s/blob/%s", baseDownloadURL, matches[1]), nil
}
