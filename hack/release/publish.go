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
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// Command to publish release to remote.
var publishCommand = &cli.Command{
	Name:  "publish",
	Usage: "Publish release to remote",
	Flags: []cli.Flag{
		versionFlag,
		imageFlag,
		archFlag,
		registryFlag,
		hashreleaseFlag,
		skipValidationFlag,
		createGithubReleaseFlag,
		githubTokenFlag,
		draftGithubReleaseFlag,
	},
	Before: publishBefore,
	Action: publishAction,
}

// Pre-action for publish command.
// It configures logging and performs validations.
var publishBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	configureLogging(c)

	var err error
	ctx, err = addRepoInfoToCtx(ctx, c.String(gitRepoFlag.Name))
	if err != nil {
		return ctx, err
	}

	// Skip validations if requested
	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validation as requested.", c.Name)
		return ctx, nil
	}

	// If building a hashrelease, publishGithubRelease must be false
	if c.Bool(hashreleaseFlag.Name) && c.Bool(createGithubReleaseFlag.Name) {
		return ctx, fmt.Errorf("cannot publish GitHub release for hashrelease builds")
	}

	// If publishing a GitHub release, ideally it should be in draft mode with a token provided.
	if c.Bool(createGithubReleaseFlag.Name) {
		if c.Bool(draftGithubReleaseFlag.Name) {
			logrus.Warnf("Publishing GitHub release in non-draft mode.")
		}
		if c.String(githubTokenFlag.Name) == "" {
			return ctx, fmt.Errorf("GitHub token must be provided via --%s flag or GITHUB_TOKEN environment variable", githubTokenFlag.Name)
		}
	}

	// If not a hashrelease build, ensure version format is valid
	if valid, _ := isReleaseVersionFormat(c.String(versionFlag.Name)); !valid && !c.Bool(hashreleaseFlag.Name) {
		return ctx, fmt.Errorf("for non-release builds, the %s flag must be set", hashreleaseFlag.Name)
	}

	return ctx, nil
})

var publishAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	// Check if images are already published
	if published, err := operatorImagePublished(c); err != nil {
		return fmt.Errorf("error checking if images are already published: %w", err)
	} else if published {
		logrus.Infof("Images for version %s are already published", c.String(versionFlag.Name))
		return nil
	}

	repoRootDir, err := gitDir()
	if err != nil {
		return fmt.Errorf("error getting git directory: %w", err)
	}

	// Set up environment variables for publish
	publishEnv := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", c.String(versionFlag.Name)),
	)
	arches := c.StringSlice(archFlag.Name)
	if len(arches) > 0 {
		publishEnv = append(publishEnv, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	}
	if c.Bool(hashreleaseFlag.Name) {
		hashreleaseEnv, err := hashreleasePublishEnv(c)
		if err != nil {
			return fmt.Errorf("error preparing hashrelease publish: %w", err)
		}
		publishEnv = append(publishEnv, hashreleaseEnv...)
	} else {
		publishEnv = append(publishEnv, "RELEASE=true")
	}

	if out, err := makeInDir(repoRootDir, "release-publish-images", publishEnv...); err != nil {
		logrus.Error(out)
		return fmt.Errorf("error publishing images: %w", err)
	}

	if !c.Bool(hashreleaseFlag.Name) {
		return publishGithubRelease(ctx, c, repoRootDir)
	}

	return nil
})

func hashreleasePublishEnv(c *cli.Command) ([]string, error) {
	publishEnv := []string{fmt.Sprintf("GIT_VERSION=%s", c.String(versionFlag.Name))}

	image := c.String(imageFlag.Name)
	if image != defaultImageName {
		publishEnv = append(publishEnv, fmt.Sprintf("BUILD_IMAGE=%s", image))
		publishEnv = append(publishEnv, fmt.Sprintf("BUILD_INIT_IMAGE=%s-init", image))
	}
	registry := c.String(registryFlag.Name)
	if registry != "" && registry != quayRegistry {
		publishEnv = append(publishEnv,
			fmt.Sprintf("IMAGE_REGISTRY=%s", registry),
			fmt.Sprintf("PUSH_IMAGE_PREFIXES=%s", addTrailingSlash(registry)))
	}
	return publishEnv, nil
}

func operatorImagePublished(c *cli.Command) (bool, error) {
	registry := c.String(registryFlag.Name)
	if registry == "" {
		registry = quayRegistry
	}
	fqImage := fmt.Sprintf("%s:%s", path.Join(registry, c.String(imageFlag.Name)), c.String(versionFlag.Name))
	ref, err := name.ParseReference(fqImage)
	if err != nil {
		return false, fmt.Errorf("failed to parse image reference for %s: %w", fqImage, err)
	}

	_, err = remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return false, nil
	}
	return true, nil
}

func publishGithubRelease(ctx context.Context, c *cli.Command, repoRootDir string) error {
	if !c.Bool(createGithubReleaseFlag.Name) {
		return nil
	}

	prerelease, err := isPrereleaseEnterpriseVersion(repoRootDir)
	if err != nil {
		return fmt.Errorf("error determining if version is prerelease: %w", err)
	}

	r := &GithubRelease{
		Org:     ctx.Value(githubOrgCtxKey).(string),
		Repo:    ctx.Value(githubRepoCtxKey).(string),
		Version: c.String(versionFlag.Name),
	}
	if err := r.setupClient(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return fmt.Errorf("error setting up GitHub client: %s", err)
	}

	// Create the GitHub release in draft mode. If it is a prerelease, mark it as such.
	if err := r.Create(ctx, c.Bool(draftGithubReleaseFlag.Name), prerelease); errors.Is(err, ErrGitHubReleaseExists) {
		logrus.Warnf("GitHub release for version %s already exists", c.String(versionFlag.Name))
		logrus.Infof("To update the release, please edit it manually on GitHub: %s", r.EditURL())
	} else if err != nil {
		return fmt.Errorf("error publishing GitHub release: %s", err)
	}

	return nil
}
