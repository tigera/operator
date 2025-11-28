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

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// Command to generate release notes.
// It generates release notes for a new release by collecting release notes from merged PRs
// in the GitHub milestone corresponding to the release version.
var releaseNotesCommand = &cli.Command{
	Name:  "notes",
	Usage: "Generate release notes for a new operator release",
	Flags: []cli.Flag{
		versionFlag,
		githubTokenFlag,
		localFlag,
	},
	Before: releaseNotesBefore,
	Action: releaseNotesAction,
}

// Pre-action for "release notes" command.
// It configures logging and extracts the operator GitHub org and repo from the CLI repo flag.
var releaseNotesBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	configureLogging(c)

	var err error
	ctx, err = addRepoInfoToCtx(ctx, c.String(gitRepoFlag.Name))
	if err != nil {
		return ctx, err
	}
	return ctx, nil
})

// Action executed for "release notes" command.
var releaseNotesAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	ver := c.String(versionFlag.Name)
	logrus.WithField("version", ver).Info("Generating release notes")

	release := &GithubRelease{
		Org:     ctx.Value(githubOrgCtxKey).(string),
		Repo:    ctx.Value(githubRepoCtxKey).(string),
		Version: ver,
	}
	if err := release.setupClient(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return fmt.Errorf("error setting up GitHub client: %s", err)
	}
	// get root directory of operator git repo
	repoRootDir, err := runCommand("git", []string{"rev-parse", "--show-toplevel"}, nil)
	if err != nil {
		return fmt.Errorf("error getting git root directory: %s", err)
	}
	return release.GenerateNotes(ctx, repoRootDir, c.Bool(localFlag.Name))
})
