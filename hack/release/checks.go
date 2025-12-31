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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	checkedVersionCtxKey contextKey = "checked-version"
)

// check that the git working tree is clean.
var checkGitClean = func(ctx context.Context) (context.Context, error) {
	version, err := gitVersion()
	if err != nil {
		return ctx, fmt.Errorf("error getting git version: %w", err)
	}
	if strings.Contains(version, "dirty") {
		return ctx, fmt.Errorf("git working tree is dirty, please commit or stash changes before proceeding")
	}
	return ctx, nil
}

// check that the provided version matches the git version.
// This is required for releases, but skipped for hashreleases.
var checkVersionMatchesGitVersion = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	if val, ok := ctx.Value(checkedVersionCtxKey).(bool); ok && val {
		return ctx, nil
	}
	ctx = context.WithValue(ctx, checkedVersionCtxKey, true)
	version := c.String(versionFlag.Name)
	checkLog := logrus.WithField("version", version)
	if c.Bool(hashreleaseFlag.Name) {
		checkLog.Debug("Skipping version check for hashrelease")
		return ctx, nil
	}
	gitVer, err := gitVersion()
	if err != nil {
		return ctx, fmt.Errorf("getting git version: %w", err)
	}
	checkLog.WithField("git-version", gitVer).Debug("Checking version matches git version")
	checkLog.Info("Using versions")
	if version != gitVer {
		return ctx, fmt.Errorf("provided version %s does not match git version %s. This is required for releases. \n"+
			"If building a hashrelease, use either the --%s flag or set environment variable %s=true", version, gitVer, hashreleaseFlag.Name, hashreleaseFlagEnvVar)
	}
	return ctx, nil
}
