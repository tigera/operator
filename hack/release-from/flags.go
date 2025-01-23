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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var debugFlag = &cli.BoolFlag{
	Name:    "debug",
	Usage:   "Enable debug logging",
	Sources: cli.EnvVars("DEBUG"),
}

var gitRemoteFlag = &cli.StringFlag{
	Name:    "remote",
	Usage:   "The git remote to push the release to",
	Value:   "origin",
	Sources: cli.EnvVars("GIT_REMOTE"),
}

var baseOperatorFlag = &cli.StringFlag{
	Name:     "base-version",
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

var devTagSuffixFlag = &cli.StringFlag{
	Name:    "dev-tag-suffix",
	Usage:   "The suffix used to denote development tags",
	Sources: cli.EnvVars("DEV_TAG_SUFFIX"),
	Value:   "0-dev",
}

var versionFlag = &cli.StringFlag{
	Name:     "version",
	Usage:    "The version of the operator to release",
	Sources:  cli.EnvVars("OPERATOR_VERSION", "VERSION"),
	Required: true,
	Action: func(ctx context.Context, c *cli.Command, value string) error {
		if value == c.String("base-version") {
			return fmt.Errorf("version cannot be the same as base-version")
		}
		if regexp.MustCompile(releaseFormat).MatchString(value) {
			logrus.Warn("You are releasing a new operator version.")
			return nil
		}
		if !regexp.MustCompile(fmt.Sprintf(hashreleaseFormat, c.String(devTagSuffixFlag.Name))).MatchString(value) {
			if c.Bool(publishFlag.Name) && c.String(registryFlag.Name) == quayRegistry && c.String(imageFlag.Name) == defaultImageName {
				return fmt.Errorf("cannot use the default registry and image for publishing operator version %q. "+
					"Either update registry and/or image flag OR specify version in the format ", value)
			}
		}
		return nil
	},
}

var exceptCalicoFlag = &cli.StringSliceFlag{
	Name:    "except-calico",
	Usage:   "Calico image and version to update where the image name adheres with config/calico_versions.yaml file. Can be specified multiple times.",
	Sources: cli.EnvVars("OS_IMAGES_VERSIONS"),
	Action:  validateOverrides,
}

var exceptEnterpriseFlag = &cli.StringSliceFlag{
	Name:    "except-calico-enterprise",
	Usage:   "Enterprise image and version to update where image name adheres with config/enterprise_versions.yaml file. Can be specified multiple times.",
	Sources: cli.EnvVars("EE_IMAGES_VERSIONS"),
	Action: func(ctx context.Context, c *cli.Command, values []string) error {
		if len(values) == 0 && len(c.StringSlice("except-calico")) == 0 {
			return fmt.Errorf("at least one of --except-calico or --except-enterprise must be set")
		}
		return validateOverrides(ctx, c, values)
	},
}

func validateOverrides(ctx context.Context, c *cli.Command, values []string) error {
	for _, value := range values {
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid override %q, must be in the format <image>:<version>", value)
		}
	}
	return nil
}

var (
	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:    "architecture",
		Aliases: []string{"arch"},
		Usage:   "The architecture(s) for the release. Can be specified multiple times.",
		Sources: cli.EnvVars("ARCHS"),
		Value:   archOptions,
		Action: func(ctx context.Context, c *cli.Command, values []string) error {
			for _, arch := range values {
				if !contains(archOptions, arch) {
					return fmt.Errorf("invalid architecture %s", arch)
				}
			}
			return nil
		},
	}
)

var registryFlag = &cli.StringFlag{
	Name:    "registry",
	Usage:   "The registry to push the new operator to (ONLY for hashreleases operator).",
	Sources: cli.EnvVars("REGISTRY"),
	Value:   quayRegistry,
}

var imageFlag = &cli.StringFlag{
	Name:    "image",
	Usage:   "The image name to use for the new operator (ONLY for hashreleases operator).",
	Sources: cli.EnvVars("IMAGE_NAME"),
	Value:   defaultImageName,
}

var publishFlag = &cli.BoolFlag{
	Name:    "publish",
	Usage:   "Publish the new operator",
	Sources: cli.EnvVars("PUBLISH"),
	Value:   false,
}
