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
	"regexp"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// Context keys for branch/prep commands
const (
	branchNameCtxKey              contextKey = "branch-name"
	baseBranchCtxKey              contextKey = "base-branch"
	calicoConfigVersionCtxKey     contextKey = "calico-config-version"
	enterpriseConfigVersionCtxKey contextKey = "enterprise-config-version"
)

var (
	// releaseBranchFormat matches release branches with a version suffix (e.g. release-v1.2).
	releaseBranchFormat = `^(%s-v\d+\.\d+)$`

	// streamFormat validates the stream flag value (e.g. v1.43).
	streamFormat = `^v\d+\.\d+$`

	defaultBaseBranch = "master"

	changedFiles = []string{
		calicoConfig,
		enterpriseConfig,
		"pkg/components",
		"pkg/imports/crds",
		"pkg/imports/admission",
	}
)

var branchCommand = &cli.Command{
	Name:  "branch",
	Usage: "Create a new branch for the release",
	Description: `The branch command creates a new branch for the release off of the current branch (which should be master or a release branch).
	The new branch name is in the format <release-branch-prefix>-<stream> (e.g. release-v1.43).

	The config versions are updated based on the provided Calico and Enterprise refs, which should point to branches or tags in the respective repositories.
	If the base branch is not a release branch, an empty commit and dev tag are also created on the base branch to allow for proper versioning of future commits on the base branch.`,
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
		skipBranchCheckFlag,
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

	// Only warn about non-default base branch for the branch command;
	// prep is expected to run from a release branch.
	if c.Name == "branch" {
		if baseBranch, ok := ctx.Value(baseBranchCtxKey).(string); ok && baseBranch != defaultBaseBranch {
			logrus.WithFields(logrus.Fields{
				"base":     baseBranch,
				"expected": defaultBaseBranch,
			}).Warn("Current branch is not the default base branch")
		}
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
	currentBranch, err := git("branch", "--show-current")
	if err != nil {
		return ctx, fmt.Errorf("getting current branch: %w", err)
	}
	ctx = context.WithValue(ctx, baseBranchCtxKey, currentBranch)
	ctx = context.WithValue(ctx, branchNameCtxKey, fmt.Sprintf("%s-%s", c.String(releaseBranchPrefixFlag.Name), c.String(streamFlag.Name)))
	if calicoRef := c.String(calicoRefFlag.Name); calicoRef != "" {
		ctx = context.WithValue(ctx, calicoConfigVersionCtxKey, calicoRef)
	}
	if enterpriseRef := c.String(enterpriseRefFlag.Name); enterpriseRef != "" {
		ctx = context.WithValue(ctx, enterpriseConfigVersionCtxKey, enterpriseRef)
	}
	return ctx, nil
}

var isValidStream = func(stream string) (bool, error) {
	matched, err := regexp.MatchString(streamFormat, stream)
	if err != nil {
		return false, fmt.Errorf("validating stream format: %w", err)
	}
	return matched, nil
}

var isReleaseBranch = func(releaseBranchPrefix, branch string) (bool, error) {
	matched, err := regexp.MatchString(fmt.Sprintf(releaseBranchFormat, regexp.QuoteMeta(releaseBranchPrefix)), branch)
	if err != nil {
		return false, fmt.Errorf("validating release branch format: %w", err)
	}
	return matched, nil
}

// refExistsInRemote checks if a ref exists in the ls-remote output by matching the full ref name.
func refExistsInRemote(lsRemoteOutput, ref string) bool {
	for _, line := range strings.Split(lsRemoteOutput, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// ls-remote output format: <hash>\trefs/heads/<name> or refs/tags/<name>
		remoteRef := parts[1]
		// Strip known prefixes to get the full ref name (preserving slashes in ref names)
		name := remoteRef
		for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
			if trimmed, ok := strings.CutPrefix(remoteRef, prefix); ok {
				name = trimmed
				break
			}
		}
		if name == ref {
			return true
		}
	}
	return false
}

// validateBranchRefs validates that the required ref flags are set for branch creation.
//   - check that the stream flag is in the correct format
//   - check that the operator branch does not already exist
//   - check that both calico and enterprise refs are provided
//   - check that the provided calico and enterprise refs exist as a branch or tag in the remote repository
//   - check that the base operator branch is either a release branch (or master) (if not skipping branch check)
var validateBranchRefs = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	// check that the stream format is valid
	stream := c.String(streamFlag.Name)
	if valid, err := isValidStream(stream); err != nil {
		return ctx, err
	} else if !valid {
		return ctx, fmt.Errorf("stream %q is not valid, expected format: vX.Y (e.g., v1.43)", stream)
	}

	// check that the operator branch does not already exist
	remote := c.String(gitRemoteFlag.Name)
	branchName, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return ctx, err
	}
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
		{calicoRef, c.String(calicoGitRepoFlag.Name), calicoRefFlag.Name},
		{enterpriseRef, c.String(enterpriseGitRepoFlag.Name), enterpriseRefFlag.Name},
	} {
		out, err := git("ls-remote", "--heads", "--tags", fmt.Sprintf("git@github.com:%s", check.repo), check.ref)
		if err != nil {
			return ctx, fmt.Errorf("checking if ref %q exists in %s: %w", check.ref, check.repo, err)
		}
		if !refExistsInRemote(out, check.ref) {
			return ctx, fmt.Errorf("ref %q not found as a branch or tag in %s", check.ref, check.repo)
		}
	}

	// check operator base branch is either the default base branch or a release branch (if not skipping branch check)
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return ctx, err
	}
	if c.Bool(skipBranchCheckFlag.Name) {
		logrus.Warnf("Skipping branch validation as requested.")
		return ctx, nil
	}
	releaseBranch, err := isReleaseBranch(c.String(releaseBranchPrefixFlag.Name), baseBranch)
	if err != nil {
		return ctx, fmt.Errorf("validating current branch: %w", err)
	}
	if baseBranch != defaultBaseBranch && !releaseBranch {
		return ctx, fmt.Errorf("current branch is %s, please switch to %s or a release branch before running this command or use --%s to skip this check", baseBranch, defaultBaseBranch, skipBranchCheckFlag.Name)
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
	remote := c.String(gitRemoteFlag.Name)
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return err
	}
	branchName, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return err
	}
	refs := []string{branchName}

	if _, err := branchActionCommon(ctx, c, fmt.Sprintf("build: update config for %s", stream)); err != nil {
		return err
	}
	logrus.WithField("newBranch", branchName).Info("Created new branch")

	// If this was not branched off a release branch, switch back to baseBranch branch to create the dev tag.
	// The dev tag goes on an empty commit on the baseBranch branch so that git describe --tags
	// produces sensible versions for subsequent baseBranch branch commits.
	var nextDevTag string
	releaseBranch, err := isReleaseBranch(c.String(releaseBranchPrefixFlag.Name), baseBranch)
	if err != nil {
		return fmt.Errorf("checking if base branch is a release branch: %w", err)
	}
	version, err := semver.Parse(fmt.Sprintf("%s.0", strings.TrimPrefix(stream, "v")))
	if err != nil {
		logrus.WithField("stream", stream).Warn("Cannot create a valid semver off stream")
	} else if !releaseBranch {
		refs = append(refs, baseBranch)
		if err := version.IncrementMinor(); err != nil {
			return fmt.Errorf("incrementing minor version: %w", err)
		}
		nextDevTag = fmt.Sprintf("v%s-%s", version.String(), c.String(devTagSuffixFlag.Name))
		refs = append(refs, nextDevTag)
		if out, err := git("switch", baseBranch); err != nil {
			logrus.Error(out)
			return fmt.Errorf("switching back to %s: %w", baseBranch, err)
		}
		if out, err := git("commit", "--allow-empty", "-m", fmt.Sprintf("Start development on v%d.%d", version.Major, version.Minor)); err != nil {
			logrus.Error(out)
			return fmt.Errorf("creating empty commit on %s: %w", baseBranch, err)
		}
		if out, err := git("tag", nextDevTag, "-m", fmt.Sprintf("%s development", version)); err != nil {
			logrus.Error(out)
			return fmt.Errorf("creating git tag %s: %w", nextDevTag, err)
		}
		logrus.WithField("devTag", nextDevTag).Infof("Created dev tag on %s", baseBranch)
	}

	if c.Bool(localFlag.Name) {
		logrus.WithFields(logrus.Fields{
			"remote":     remote,
			"baseBranch": baseBranch,
			"newBranch":  branchName,
			"newDevTag":  nextDevTag,
		}).Warn("Local flag is set, skipping pushing to remote")
		return nil
	}

	// Push refs to remote - release branch, base branch (with empty commit), and dev tag
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if out, err := git("push", remote, ref); err != nil {
			logrus.Error(out)
			return fmt.Errorf("pushing %s to remote: %w", ref, err)
		}
		logrus.WithFields(logrus.Fields{
			"ref":    ref,
			"remote": remote,
		}).Infof("Pushed to %s", remote)
	}
	return nil
})

var branchCleanupFns []func()

var branchAfter = cli.AfterFunc(func(_ context.Context, _ *cli.Command) error {
	for i := len(branchCleanupFns) - 1; i >= 0; i-- {
		branchCleanupFns[i]()
	}
	return nil
})

func switchBranch(ctx context.Context, branchName string) error {
	// get current branch to switch back to later
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return err
	}
	branchCleanupFns = append(branchCleanupFns, func() {
		if out, err := git("switch", "-f", baseBranch); err != nil {
			logrus.Error(out)
			logrus.WithError(err).Errorf("Failed to reset to %q branch", baseBranch)
		}
	})
	if out, err := git("switch", "-C", branchName); err != nil {
		logrus.Error(out)
		return fmt.Errorf("creating and switching to branch %s: %w", branchName, err)
	}
	return nil
}

// branchActionCommon switches to a new branch, modifies config versions, and commits the changes.
// It reads the branch name and calico/enterprise versions from context (set by Before functions).
// It returns the repo root directory for subsequent operations.
func branchActionCommon(ctx context.Context, c *cli.Command, commitMsg string) (string, error) {
	branchName, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return "", err
	}
	if err := switchBranch(ctx, branchName); err != nil {
		return "", err
	}
	repoRootDir, err := gitDir()
	if err != nil {
		return "", fmt.Errorf("getting git directory: %w", err)
	}
	if err := modifyConfigVersions(ctx, c, repoRootDir); err != nil {
		return "", fmt.Errorf("modifying config versions: %w", err)
	}
	if err := commitConfigChanges(repoRootDir, commitMsg); err != nil {
		return "", fmt.Errorf("committing config changes: %w", err)
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
			return fmt.Errorf("modifying Calico config: %w", err)
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
			return fmt.Errorf("modifying Enterprise config: %w", err)
		}
		// Update registry for Enterprise
		if eRegistry := c.String(enterpriseRegistryFlag.Name); eRegistry != "" {
			logrus.Debugf("Updating Enterprise registry to %s", eRegistry)
			if err := modifyComponentImageConfig(repoRootDir, componentImageConfigRelPath, enterpriseRegistryConfigKey, eRegistry); err != nil {
				return fmt.Errorf("modifying Enterprise registry config: %w", err)
			}
		}
		// Set ENTERPRISE_CRDS_DIR if specified
		if crdsDir := c.String(enterpriseDirFlag.Name); crdsDir != "" {
			logrus.Warnf("Using local Enterprise CRDs from %s", crdsDir)
			env = append(env, fmt.Sprintf("ENTERPRISE_CRDS_DIR=%s", crdsDir))
		}
	}

	// Run make target to ensure files are formatted correctly and generated files are up to date.
	if out, err := makeInDir(repoRootDir, strings.Join(makeTargets, " "), env...); err != nil {
		logrus.Error(out)
		return fmt.Errorf("running \"make %s\": %w", strings.Join(makeTargets, " "), err)
	}
	return nil
}

func commitConfigChanges(repoRootDir, msg string) error {
	if out, err := gitInDir(repoRootDir, append([]string{"add"}, changedFiles...)...); err != nil {
		logrus.Error(out)
		return fmt.Errorf("staging git changes: %w", err)
	}
	if out, err := git("commit", "-m", msg); err != nil {
		logrus.Error(out)
		return fmt.Errorf("committing git changes: %w", err)
	}
	return nil
}
