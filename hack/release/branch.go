// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Context keys for branch/prep commands
const (
	branchNameCtxKey              contextKey = "branch-name"
	calicoConfigVersionCtxKey     contextKey = "calico-config-version"
	enterpriseConfigVersionCtxKey contextKey = "enterprise-config-version"
)

var branchCommand = &cli.Command{
	Name:        "branch",
	Usage:       "Create a new branch for the release",
	Description: "This command creates a new branch for the release.",
	Flags: []cli.Flag{
		streamFlag,
		calicoRefFlag,
		calicoGitRepoFlag,
		enterpriseRefFlag,
		enterpriseGitRepoFlag,
		releaseBranchPrefixFlag,
		devTagSuffixFlag,
		calicoDirFlag,
		enterpriseDirFlag,
		enterpriseRegistryFlag,
		skipValidationFlag,
		localFlag,
		gitRemoteFlag,
	},
	Before: branchBefore,
	Action: branchAction,
	After:  branchAfter,
}

// branchBeforeCommon handles shared Before logic for both branch and prep
func branchBeforeCommon(ctx context.Context, c *cli.Command, scopeContextFn func(context.Context, *cli.Command) (context.Context, error), validateFn func(context.Context, *cli.Command) (context.Context, error)) (context.Context, error) {
	configureLogging(c)

	// Start with a clean slate for branch cleanup functions.
	branchCleanupFns = nil

	var err error
	ctx, err = scopeContextFn(ctx, c)
	if err != nil {
		return ctx, err
	}

	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validations as requested.", c.Name)
		return ctx, nil
	}

	ctx, err = checkGitClean(ctx)
	if err != nil {
		return ctx, err
	}
	return validateFn(ctx, c)
}

// branchContextValuesFunc sets branch cutting context values based on CLI flags
var branchContextValuesFunc = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	ctx = context.WithValue(ctx, branchNameCtxKey, fmt.Sprintf("%s-%s", c.String(releaseBranchPrefixFlag.Name), c.String(streamFlag.Name)))
	if calicoRef := c.String(calicoRefFlag.Name); calicoRef != "" {
		ctx = context.WithValue(ctx, calicoConfigVersionCtxKey, calicoRef)
	}
	if enterpriseRef := c.String(enterpriseRefFlag.Name); enterpriseRef != "" {
		ctx = context.WithValue(ctx, enterpriseConfigVersionCtxKey, enterpriseRef)
	}
	return ctx, nil
}

// validateBranchRefs validates that the required ref flags are set for branch creation.
//   - check that the operator branch does not already exist
//   - check that both calico and enterprise refs are provided
//   - check that the provided calico and enterprise refs exist as a branch or tag in the remote repository
var validateBranchRefs = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	// check that the operator branch does not already exist
	remote := c.String(gitRemoteFlag.Name)
	branchName := ctx.Value(branchNameCtxKey).(string)
	out, err := git("ls-remote", "--heads", remote, branchName)
	if err != nil {
		return ctx, fmt.Errorf("checking if branch %s exists in remote %s: %w", branchName, remote, err)
	}
	if out != "" {
		return ctx, fmt.Errorf("branch %s already exists in remote %s, please choose a different name or delete the existing branch", branchName, remote)
	}

	// check that both calico and enterprise refs are provided
	calicoRef := c.String(calicoRefFlag.Name)
	enterpriseRef := c.String(enterpriseRefFlag.Name)
	if calicoRef == "" || enterpriseRef == "" {
		return ctx, fmt.Errorf("both --%s and --%s are required for branch creation", calicoRefFlag.Name, enterpriseRefFlag.Name)
	}

	// check that the provided calico and enterprise refs exist as a branch or tag in the remote repository
	for _, check := range []struct {
		ref  string
		repo string
		flag string
	}{
		{calicoRef, calicoGitRepoFlag.Value, calicoRefFlag.Name},
		{enterpriseRef, enterpriseGitRepoFlag.Value, enterpriseRefFlag.Name},
	} {
		out, err := git("ls-remote", "--branches", "--tags", fmt.Sprintf("git@github.com:%s", check.repo), check.ref)
		if err != nil {
			return ctx, fmt.Errorf("checking if ref %q exists in %s: %w", check.ref, check.repo, err)
		}
		if !strings.Contains(out, check.ref) {
			return ctx, fmt.Errorf("ref %q not found as a branch or tag in %s", check.ref, check.repo)
		}
	}
	return ctx, nil
}

// Pre-action for branch command.
var branchBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	return branchBeforeCommon(ctx, c, branchContextValuesFunc, validateBranchRefs)
})

// Action for branch command.
var branchAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	stream := c.String(streamFlag.Name)
	branchName := ctx.Value(branchNameCtxKey).(string)
	remote := c.String(gitRemoteFlag.Name)

	if _, err := branchActionCommon(ctx, c, fmt.Sprintf("build: update config for %s", stream)); err != nil {
		return err
	}
	// We are now on the release branch with config changes committed.

	// Switch back to master to create the dev tag.
	// The dev tag goes on an empty commit on master so that git describe --tags
	// produces sensible versions for subsequent master commits.
	if _, err := git("switch", "master"); err != nil {
		return fmt.Errorf("error switching back to master: %w", err)
	}
	version := fmt.Sprintf("%s.0", stream)
	devTag := fmt.Sprintf("%s-%s", version, c.String(devTagSuffixFlag.Name))
	if _, err := git("commit", "--allow-empty", "-m", fmt.Sprintf("Start development on %s", stream)); err != nil {
		return fmt.Errorf("error creating empty commit on master: %w", err)
	}
	if _, err := git("tag", devTag); err != nil {
		return fmt.Errorf("error creating git tag %s: %w", devTag, err)
	}
	logrus.Infof("Created branch %s and tagged master with %s", branchName, devTag)

	if c.Bool(localFlag.Name) {
		logrus.Warnf("Local flag is set, skipping pushing to remote")
		return nil
	}

	// Push release branch, master (with empty commit), and dev tag to remote
	if _, err := git("push", remote, branchName); err != nil {
		return fmt.Errorf("error pushing %s to remote: %w", branchName, err)
	}
	logrus.Infof("Pushed %s to remote", branchName)
	if _, err := git("push", remote, "HEAD:master"); err != nil {
		return fmt.Errorf("error pushing master to remote: %w", err)
	}
	logrus.Info("Pushed master with dev commit to remote")
	if _, err := git("push", remote, devTag); err != nil {
		return fmt.Errorf("error pushing tag %s to remote: %w", devTag, err)
	}
	logrus.Infof("Pushed tag %s to remote", devTag)
	return nil
})

var branchCleanupFns []func()

var branchAfter = cli.AfterFunc(func(_ context.Context, _ *cli.Command) error {
	for i := len(branchCleanupFns) - 1; i >= 0; i-- {
		branchCleanupFns[i]()
	}
	return nil
})

func switchBranch(branchName string) error {
	// get current branch to switch back to later
	baseBranch, err := git("branch", "--show-current")
	if err != nil {
		return fmt.Errorf("error getting current branch: %w", err)
	}
	branchCleanupFns = append(branchCleanupFns, func() {
		if _, err := git("switch", "-f", baseBranch); err != nil {
			logrus.WithError(err).Errorf("Failed to reset to %q branch", baseBranch)
		}
	})
	if _, err := git("switch", "-C", branchName); err != nil {
		return fmt.Errorf("error creating and switching to branch %s: %w", branchName, err)
	}
	return nil
}

// branchActionCommon switches to a new branch, modifies config versions, and commits the changes.
// It reads the branch name and calico/enterprise versions from context (set by Before functions).
// It returns the repo root directory for subsequent operations.
func branchActionCommon(ctx context.Context, c *cli.Command, commitMsg string) (string, error) {
	branchName := ctx.Value(branchNameCtxKey).(string)
	if err := switchBranch(branchName); err != nil {
		return "", err
	}
	repoRootDir, err := gitDir()
	if err != nil {
		return "", fmt.Errorf("error getting git directory: %w", err)
	}
	if err := modifyConfigVersions(ctx, c, repoRootDir); err != nil {
		return "", fmt.Errorf("error modifying config versions: %w", err)
	}
	if err := commitConfigChanges(repoRootDir, commitMsg); err != nil {
		return "", fmt.Errorf("error committing config changes: %w", err)
	}
	return repoRootDir, nil
}

// modifyConfigVersions updates config versions and runs make targets to regenerate files.
// It reads calico/enterprise versions from context (set by Before functions).
func modifyConfigVersions(ctx context.Context, c *cli.Command, repoRootDir string) error {
	calicoVersion, _ := ctx.Value(calicoConfigVersionCtxKey).(string)
	enterpriseVersion, _ := ctx.Value(enterpriseConfigVersionCtxKey).(string)
	makeTargets := []string{"fix"}
	env := os.Environ()
	if calicoVersion != "" {
		makeTargets = append(makeTargets, "gen-versions-calico")
		if err := updateConfigVersions(repoRootDir, calicoConfig, calicoVersion); err != nil {
			return fmt.Errorf("error modifying Calico config: %w", err)
		}
		// Set CALICO_CRDS_DIR if specified
		if crdsDir := c.String(calicoDirFlag.Name); crdsDir != "" {
			logrus.Warnf("Using local Calico CRDs from %s", crdsDir)
			env = append(env, fmt.Sprintf("CALICO_CRDS_DIR=%s", crdsDir))
		}
	}
	if enterpriseVersion != "" {
		makeTargets = append(makeTargets, "gen-versions-enterprise")
		if err := updateConfigVersions(repoRootDir, enterpriseConfig, enterpriseVersion); err != nil {
			return fmt.Errorf("error modifying Enterprise config: %w", err)
		}
		// Update registry for Enterprise
		if eRegistry := c.String(enterpriseRegistryFlag.Name); eRegistry != "" {
			logrus.Debugf("Updating Enterprise registry to %s", eRegistry)
			if err := modifyComponentImageConfig(repoRootDir, componentImageConfigRelPath, enterpriseRegistryConfigKey, eRegistry); err != nil {
				return fmt.Errorf("error modifying Enterprise registry config: %w", err)
			}
		}
		// Set ENTERPRISE_CRDS_DIR if specified
		if crdsDir := c.String(enterpriseDirFlag.Name); crdsDir != "" {
			logrus.Warnf("Using local Enterprise CRDs from %s", crdsDir)
			env = append(env, fmt.Sprintf("ENTERPRISE_CRDS_DIR=%s", crdsDir))
		}
	}

	// Run make target to ensure files are formatted correctly and generated files are up to date.
	if _, err := makeInDir(repoRootDir, strings.Join(makeTargets, " "), env...); err != nil {
		return fmt.Errorf("error running \"make %s\": %w", strings.Join(makeTargets, " "), err)
	}
	return nil
}

func commitConfigChanges(repoRootDir, msg string) error {
	if _, err := gitInDir(repoRootDir, append([]string{"add"}, changedFiles...)...); err != nil {
		return fmt.Errorf("error staging git changes: %w", err)
	}
	if _, err := git("commit", "-m", msg); err != nil {
		return fmt.Errorf("error committing git changes: %w", err)
	}
	return nil
}
