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
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "operator-from",
		Usage: "CLI tool for releasing operator using a previous release",
		Flags: []cli.Flag{
			baseOperatorFlag,
			versionFlag,
			exceptCalicoFlag,
			exceptEnterpriseFlag,
			publishFlag,
			archFlag,
			gitRemoteFlag,
			registryFlag,
			imageFlag,
			devTagSuffixFlag,
			debugFlag,
		},
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			if c.Bool(debugFlag.Name) {
				logrus.SetLevel(logrus.DebugLevel)
			}
			// check if git repo is dirty
			if version, err := gitVersion(); err != nil {
				return ctx, fmt.Errorf("error getting git version: %s", err)
			} else if strings.Contains(version, "dirty") {
				return ctx, fmt.Errorf("git repo is dirty, please commit changes before releasing")
			}
			return ctx, nil
		},
		Action: releaseFrom,
	}

	// Run the app.
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logrus.WithError(err).Fatal("Error building new operator")
	}
}
