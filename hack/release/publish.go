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
		if !c.Bool(draftGithubReleaseFlag.Name) {
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
	repoRootDir, err := gitDir()
	if err != nil {
		return fmt.Errorf("getting git directory: %w", err)
	}
	if err := publishImages(c, repoRootDir); err != nil {
		return err
	}
	if c.Bool(hashreleaseFlag.Name) {
		return nil
	}
	if !c.Bool(createGithubReleaseFlag.Name) {
		logrus.Warnf("Skipping GitHub release creation. Either use %q to create a GitHub release or create manually.", publicCommand.FullName())
		return nil
	}
	return publishGithubRelease(ctx, c, repoRootDir)
})

func publishImages(c *cli.Command, repoRootDir string) error {
	version := c.String(versionFlag.Name)
	log := logrus.WithField("version", version)
	// Check if images are already published
	if published, err := operatorImagePublished(c); err != nil {
		return fmt.Errorf("checking if images are already published: %w", err)
	} else if published {
		log.Warn("Images are already published")
		return nil
	}

	// Set up environment variables for publish
	publishEnv := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", version),
	)
	if arches := c.StringSlice(archFlag.Name); len(arches) > 0 {
		log = log.WithField("arches", arches)
		publishEnv = append(publishEnv, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	}
	if image := c.String(imageFlag.Name); image != defaultImageName {
		log = log.WithField("image", image)
		publishEnv = append(publishEnv, fmt.Sprintf("BUILD_IMAGE=%s", image))
		publishEnv = append(publishEnv, fmt.Sprintf("BUILD_INIT_IMAGE=%s-init", image))
	}
	if registry := c.String(registryFlag.Name); registry != "" && registry != quayRegistry {
		log = log.WithField("registry", registry)
		publishEnv = append(publishEnv,
			fmt.Sprintf("IMAGE_REGISTRY=%s", registry),
			fmt.Sprintf("PUSH_IMAGE_PREFIXES=%s", addTrailingSlash(registry)))
	}
	if c.Bool(hashreleaseFlag.Name) {
		log = log.WithField("hashrelease", true)
		publishEnv = append(publishEnv, fmt.Sprintf("GIT_VERSION=%s", version))
	} else {
		log = log.WithField("release", true)
		publishEnv = append(publishEnv, "RELEASE=true")
	}

	log.Info("Publishing Operator images")
	if out, err := makeInDir(repoRootDir, "release-publish-images", publishEnv...); err != nil {
		log.Error(out)
		return fmt.Errorf("publishing images: %w", err)
	}
	log.Info("Successfully published Operator images")
	return nil
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
	version := c.String(versionFlag.Name)
	prerelease, err := isPrereleaseEnterpriseVersion(repoRootDir)
	if err != nil {
		return fmt.Errorf("determining if version is prerelease: %w", err)
	}
	r := &GithubRelease{
		Org:     ctx.Value(githubOrgCtxKey).(string),
		Repo:    ctx.Value(githubRepoCtxKey).(string),
		Version: version,
	}
	if err := r.setupClient(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return fmt.Errorf("setting up GitHub client: %s", err)
	}
	// Create the GitHub release in draft mode. If it is a prerelease, mark it as such.
	if err := r.Create(ctx, c.Bool(draftGithubReleaseFlag.Name), prerelease); errors.Is(err, ErrGitHubReleaseExists) {
		// Do not error out if the release already exists.
		return nil
	} else if err != nil {
		return fmt.Errorf("publishing GitHub release: %s", err)
	}
	return nil
}
