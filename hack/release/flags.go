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
	"regexp"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
)

var debugFlag = &cli.BoolFlag{
	Name:    "debug",
	Usage:   "Enable debug logging",
	Sources: cli.EnvVars("DEBUG"),
}

// Git/GitHub related flags.
var (
	githubFlagCategory = "GitHub Options"
	gitRemoteFlag      = &cli.StringFlag{
		Name:    "remote",
		Usage:   "The git remote to push the release to",
		Value:   "origin",
		Sources: cli.EnvVars("GIT_REMOTE"),
	}
	gitRepoFlag = &cli.StringFlag{
		Name:    "repo",
		Usage:   "The git repository to use",
		Value:   mainRepo,
		Sources: cli.EnvVars("REPO"),
	}
	githubTokenFlag = &cli.StringFlag{
		Name:     "github-token",
		Category: githubFlagCategory,
		Usage:    "GitHub token to use for interacting with the GitHub API",
		Sources:  cli.EnvVars("GITHUB_TOKEN"),
		Required: true,
	}
	skipMilestoneFlag = &cli.BoolFlag{
		Name:     "skip-milestone",
		Category: githubFlagCategory,
		Usage:    "Skip updating GitHub milestones",
		Sources:  cli.EnvVars("SKIP_MILESTONE"),
		Value:    false,
		Action: func(ctx context.Context, c *cli.Command, skipMilestone bool) error {
			// If not on the main repo, skip-milestone must be true
			if c.String(gitRepoFlag.Name) != mainRepo && !skipMilestone {
				return fmt.Errorf("skip-milestone must be true when using a forked repo")
			}
			return nil
		},
	}
)

// Operator flags
var (
	operatorFlagCategory = "Operator Options"
	devTagSuffixFlag     = &cli.StringFlag{
		Name:     "dev-tag-suffix",
		Category: operatorFlagCategory,
		Usage:    "The suffix used to denote development tags",
		Sources:  cli.EnvVars("DEV_TAG_SUFFIX"),
		Value:    "0-dev",
	}
	versionFlag = &cli.StringFlag{
		Name:     "version",
		Category: operatorFlagCategory,
		Usage:    "The version of the operator to release",
		Sources:  cli.EnvVars("OPERATOR_VERSION", "VERSION"),
		Required: true,
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if valid, err := isReleaseVersionFormat(s); err != nil {
				return fmt.Errorf("error validating version format: %w", err)
			} else if !valid {
				return fmt.Errorf("version %q is not a valid release version", s)
			}
			return nil
		},
	}
	baseOperatorFlag = &cli.StringFlag{
		Name:     "base-version",
		Category: operatorFlagCategory,
		Aliases:  []string{"base"},
		Usage:    "The version of the operator to use as the base for this new version.",
		Sources:  cli.EnvVars("OPERATOR_BASE_VERSION"),
		Required: true,
		Action: func(ctx context.Context, c *cli.Command, value string) error {
			if !regexp.MustCompile(fmt.Sprintf(baseVersionFormat, c.String(devTagSuffixFlag.Name))).MatchString(value) {
				return fmt.Errorf("base-version must be in the format vX.Y.Z or vX.Y.Z-<dev-tag-suffix>-n-g<git-hash>-<hashrelease-name> or " +
					"vX.Y.Z-<dev-tag-suffix>-n-g<git-hash>-<product-hashrelease-version>")
			}
			return nil
		},
	}
	imageFlag = &cli.StringFlag{
		Name:     "image",
		Category: operatorFlagCategory,
		Usage:    "The image name to use for the new operator (ONLY for hashreleases operator).",
		Sources:  cli.EnvVars("IMAGE_NAME"),
		Value:    defaultImageName,
	}
	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:     "architecture",
		Category: operatorFlagCategory,
		Aliases:  []string{"arch"},
		Usage:    "The architecture(s) for the release. Can be specified multiple times.",
		Sources:  cli.EnvVars("ARCHS"),
		Value:    archOptions,
		Action: func(ctx context.Context, c *cli.Command, values []string) error {
			for _, arch := range values {
				if !slices.Contains(archOptions, arch) {
					return fmt.Errorf("invalid architecture %s", arch)
				}
			}
			return nil
		},
	}
	registryFlag = &cli.StringFlag{
		Name:     "registry",
		Category: operatorFlagCategory,
		Usage:    "The registry to push the new operator to (ONLY for hashreleases operator).",
		Sources:  cli.EnvVars("REGISTRY"),
		Value:    quayRegistry,
	}
)

func validateOverrides(ctx context.Context, c *cli.Command, values []string) error {
	for _, value := range values {
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid override %q, must be in the format <image>:<version>", value)
		}
	}
	return nil
}

var publishFlag = &cli.BoolFlag{
	Name:    "publish",
	Usage:   "Publish the new operator",
	Sources: cli.EnvVars("PUBLISH"),
	Value:   false,
}

var localFlag = &cli.BoolFlag{
	Name:    "local",
	Usage:   "Run the release process locally",
	Sources: cli.EnvVars("LOCAL"),
	Value:   false,
}

var skipValidationFlag = &cli.BoolFlag{
	Name:    "skip-validation",
	Usage:   "Skip validation",
	Sources: cli.EnvVars("SKIP_VALIDATION"),
	Value:   false,
}

var (
	calicoFlagCategory = "Calico Options"
	calicoVersionFlag  = &cli.StringFlag{
		Name:     "calico-version",
		Category: calicoFlagCategory,
		Usage:    "The Calico version to use for the release",
		Sources:  cli.EnvVars("CALICO_VERSION"),
		Required: true,
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if valid, err := isReleaseVersionFormat(s); err != nil {
				return fmt.Errorf("error validating Calico version format: %w", err)
			} else if !valid {
				return fmt.Errorf("version %q is not a valid Calico release version", s)
			}
			return nil
		},
	}
	exceptCalicoFlag = &cli.StringSliceFlag{
		Name:     "except-calico",
		Category: calicoFlagCategory,
		Usage:    "Calico image and version to update where the image name adheres with config/calico_versions.yaml file. Can be specified multiple times.",
		Sources:  cli.EnvVars("OS_IMAGES_VERSIONS"),
		Action:   validateOverrides,
	}
)

// Enterprise related flags.
var (
	enterpriseFlagCategory = "Enterprise Options"
	enterpriseVersionFlag  = &cli.StringFlag{
		Name:     "enterprise-version",
		Category: enterpriseFlagCategory,
		Usage:    "The Calico Enterprise version to use for the release",
		Sources:  cli.EnvVars("ENTERPRISE_VERSION"),
		Required: true,
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if valid, err := isReleaseVersionFormat(s); err != nil {
				return fmt.Errorf("error validating Enterprise version format: %w", err)
			} else if !valid {
				return fmt.Errorf("version %q is not a valid Enterprise release version", s)
			}
			return nil
		},
	}
	enterpriseRegistryFlag = &cli.StringFlag{
		Name:     "enterprise-registry",
		Category: enterpriseFlagCategory,
		Usage:    "The registry Enterprise images are hosted in.",
		Sources:  cli.EnvVars("ENTERPRISE_REGISTRY"),
		Value:    quayRegistry,
	}
	exceptEnterpriseFlag = &cli.StringSliceFlag{
		Name:     "except-calico-enterprise",
		Category: enterpriseFlagCategory,
		Usage:    "Enterprise image and version to update where image name adheres with config/enterprise_versions.yaml file. Can be specified multiple times.",
		Sources:  cli.EnvVars("EE_IMAGES_VERSIONS"),
		Action: func(ctx context.Context, c *cli.Command, values []string) error {
			if len(values) == 0 && len(c.StringSlice("except-calico")) == 0 {
				return fmt.Errorf("at least one of --except-calico or --except-enterprise must be set")
			}
			return validateOverrides(ctx, c, values)
		},
	}
)
