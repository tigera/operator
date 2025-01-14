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

	"github.com/urfave/cli/v3"
)

var debugFlag = &cli.BoolFlag{
	Name:    "debug",
	Usage:   "Enable debug logging",
	Sources: cli.EnvVars("DEBUG"),
}

var remoteFlag = &cli.StringFlag{
	Name:    "remote",
	Usage:   "The git remote to push the release to",
	Value:   "origin",
	Sources: cli.EnvVars("GIT_REMOTE"),
}

var baseOperatorFlag = &cli.StringFlag{
	Name:    "base-version",
	Aliases: []string{"base"},
	Usage: "The version of the operator to base this new version from. " +
		"It is expected in the format vX.Y.Z for releases and " +
		"for hashrelease, either vX.Y.Z-n-g<git-hash>-<hashrelease-name> (legacy) or " +
		"vX.Y.Z-n-g<git-hash>-<product-hashrelease-version> (new) where product-hashrelease-version is in the format vA.B.C-u-g<product-git-hash>",
	Sources:  cli.EnvVars("OPERATOR_BASE_VERSION"),
	Required: true,
	Action: func(ctx context.Context, c *cli.Command, value string) error {
		if !regexp.MustCompile(baseVersionFormat).MatchString(value) {
			return fmt.Errorf("base-version must be in the format vX.Y.Z or vX.Y.Z-n-g<git-hash>-<hashrelease-name> or " +
				"vX.Y.Z-n-g<git-hash>-<product-hashrelease-version>")
		}
		return nil
	},
}

var versionFlag = &cli.StringFlag{
	Name:    "version",
	Usage:   "The version of the operator to release",
	Sources: cli.EnvVars("OPERATOR_VERSION", "VERSION"),
	Action: func(ctx context.Context, c *cli.Command, value string) error {
		if value == c.String("base-version") {
			return fmt.Errorf("version cannot be the same as base-version")
		}
		if !regexp.MustCompile(baseVersionFormat).MatchString(value) {
			return fmt.Errorf("base-version must be in the format vX.Y.Z or vX.Y.Z-n-g<git-hash>-<hashrelease-name> or " +
				"vX.Y.Z-n-g<git-hash>-<product-hashrelease-version>")
		}
		return nil
	},
}

var exceptCalicoFlag = &cli.StringSliceFlag{
	Name: "except-calico",
	Usage: "A list of Calico images and the version to use for them. " +
		"This should use the format based on the config/calico_versions.yaml file. " +
		"e.g. --except-calico calico/cni:vX.Y.Z --except-calico csi-node-driver-registrar:vA.B.C-n-g<git-hash>",
	Sources: cli.EnvVars("OS_IMAGES_VERSIONS"),
}

var exceptEnterpriseFlag = &cli.StringSliceFlag{
	Name:    "except-calico-enterprise",
	Aliases: []string{"except-enterprise", "except-calient"},
	Usage: "A list of Enterprise images and the versions to use for them. " +
		"This should use the format based on the config/enterprise_versions.yaml file. " +
		"e.g. --except-calico-enterprise linseed:vX.Y.Z --except-calico-enterprise security-event-webhooks-processor:vA.B.C-n-g<git-hash>",
	Sources: cli.EnvVars("EE_IMAGES_VERSIONS"),
	Action: func(ctx context.Context, c *cli.Command, values []string) error {
		if len(values) == 0 && len(c.StringSlice("except-calico")) == 0 {
			return fmt.Errorf("at least one of --except-calico or --except-enterprise must be set")
		}
		return nil
	},
}

var (
	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:    "architecture",
		Aliases: []string{"arch"},
		Usage:   "The architecture to use for the release. Repeat for multiple architectures.",
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

var publishFlag = &cli.BoolFlag{
	Name:    "publish",
	Usage:   "Publish the new operator",
	Sources: cli.EnvVars("PUBLISH"),
	Value:   false,
}
