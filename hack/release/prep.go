// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

// Patterns for components to exclude from version updates
var excludedComponentsPatterns = []string{
	`^coreos-.*`,
	`^eck-.*`,
}

var changedFiles = []string{
	calicoConfig,
	enterpriseConfig,
	"pkg/components",
	"pkg/imports/crds",
}

// Command to prepare repo for a new release.
var prepCommand = &cli.Command{
	Name:  "prep",
	Usage: "Prepare for a new release",
	Description: `This involves updating version configuration files, creating a new git branch with the changes,
pushing the branch to remote, and creating a PR against the release branch.

The Calico and Enterprise versions specified must exist as a tag in their respective GitHub repositories.
Otherwise, use the environment variables "CALICO_CRDS_DIR" and "ENTERPRISE_CRDS_DIR"
to point to local repositories for Calico and Enterprise respectively.`,
	Flags: []cli.Flag{
		versionFlag,
		calicoVersionFlag,
		calicoDirFlag,
		enterpriseVersionFlag,
		enterpriseDirFlag,
		enterpriseRegistryFlag,
		skipValidationFlag,
		skipMilestoneFlag,
		skipRepoCheckFlag,
		githubTokenFlag,
		localFlag,
	},
	Before: prepBefore,
	Action: prepAction,
}

// Pre-action for release prep command.
var prepBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	configureLogging(c)

	// Extract repo information from CLI repo flag into context
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

	// Ensure that git working tree is clean
	ctx, err = checkGitClean(ctx)
	if err != nil {
		return ctx, err
	}

	if token := c.String(githubTokenFlag.Name); token == "" && !c.Bool(localFlag.Name) {
		return ctx, fmt.Errorf("GitHub token must be provided via --%s flag or GITHUB_TOKEN environment variable", githubTokenFlag.Name)
	}

	// One of Calico or Enterprise version must be specified.
	if c.String(calicoVersionFlag.Name) == "" && c.String(enterpriseVersionFlag.Name) == "" {
		return ctx, fmt.Errorf("at least one of %s or %s must be specified", calicoVersionFlag.Name, enterpriseVersionFlag.Name)
	}

	// If Calico is not passed in, check the version in calico_versions.yml is a released version.
	// An operator release must always include a released Calico version.
	calicoVersion := c.String(calicoVersionFlag.Name)
	if calicoVersion != "" {
		return ctx, nil
	}
	dir, err := gitDir()
	if err != nil {
		return ctx, fmt.Errorf("error getting git directory: %w", err)
	}
	versions, err := calicoConfigVersions(dir, calicoConfig)
	if err != nil {
		return ctx, fmt.Errorf("error retrieving Calico version: %w", err)
	}
	calicoVersion = versions.Title
	if valid, err := isReleaseVersionFormat(calicoVersion); err != nil {
		return ctx, fmt.Errorf("error validating Calico version format: %w", err)
	} else if !valid {
		return ctx, fmt.Errorf("every release must contain a released Calico version, but found %s in %s", calicoVersion, calicoConfig)
	}
	return ctx, nil
})

// Action executed for release prep command.
var prepAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	// get current branch to switch back to later
	baseBranch, err := git("branch", "--show-current")
	if err != nil {
		return fmt.Errorf("error getting current branch: %w", err)
	}
	defer func() {
		if _, err := git("switch", "-f", baseBranch); err != nil {
			logrus.WithError(err).Errorf("Failed to reset to %q branch", baseBranch)
		}
	}()

	makeTargets := []string{"fix"}
	prepEnv := os.Environ()

	repoRootDir, err := gitDir()
	if err != nil {
		return fmt.Errorf("error getting git directory: %w", err)
	}
	version := c.String(versionFlag.Name)
	ctx = context.WithValue(ctx, versionCtxKey, version)

	// Create and switch to new branch using "switch -C" to avoid issues if the branch already exists
	prepBranch := fmt.Sprintf("build-%s", version)
	if _, err := git("switch", "-C", prepBranch); err != nil {
		return fmt.Errorf("error creating and switching to branch %s: %w", prepBranch, err)
	}

	// Modify config versions files
	if calico := c.String(calicoVersionFlag.Name); calico != "" {
		makeTargets = append(makeTargets, "gen-versions-calico")
		if err := updateConfigVersions(repoRootDir, calicoConfig, calico); err != nil {
			return fmt.Errorf("error modifying Calico config: %w", err)
		}
		// Set CALICO_CRDS_DIR if specified
		if crdsDir := c.String(calicoDirFlag.Name); crdsDir != "" {
			logrus.Warnf("Using local Calico CRDs from %s", crdsDir)
			prepEnv = append(prepEnv, fmt.Sprintf("CALICO_CRDS_DIR=%s", crdsDir))
		}
	}
	enterprise := c.String(enterpriseVersionFlag.Name)
	if enterprise != "" {
		makeTargets = append(makeTargets, "gen-versions-enterprise")
		if err := updateConfigVersions(repoRootDir, enterpriseConfig, enterprise); err != nil {
			return fmt.Errorf("error modifying Enterprise config: %w", err)
		}
		// Update registry for Enterprise
		if eRegistry := c.String(enterpriseRegistryFlag.Name); eRegistry != "" {
			logrus.Debugf("Updating Enterprise registry to %s", eRegistry)
			if err := modifyComponentImageConfig(repoRootDir, enterpriseRegistryConfigKey, eRegistry); err != nil {
				return err
			}
		}
		// Set ENTERPRISE_CRDS_DIR if specified
		if crdsDir := c.String(enterpriseDirFlag.Name); crdsDir != "" {
			logrus.Warnf("Using local Enterprise CRDs from %s", crdsDir)
			prepEnv = append(prepEnv, fmt.Sprintf("ENTERPRISE_CRDS_DIR=%s", crdsDir))
		}
	}

	// Run make target to ensure files are formatted correctly and generated files are up to date.
	if _, err := makeInDir(repoRootDir, strings.Join(makeTargets, " "), prepEnv...); err != nil {
		return fmt.Errorf("error running \"make fix gen-versions\": %w", err)
	}

	// Commit changes
	if _, err := gitInDir(repoRootDir, append([]string{"add"}, changedFiles...)...); err != nil {
		return fmt.Errorf("error staging git changes: %w", err)
	}
	if _, err := git("commit", "-m", fmt.Sprintf("build: %s release", version)); err != nil {
		return fmt.Errorf("error committing git changes: %w", err)
	}

	// If local flag is set, skip pushing prep branch and creating PR
	if c.Bool(localFlag.Name) {
		logrus.WithField("branch", prepBranch).Warn("Local flag set, no remote changes will be made")
		logrus.Infof("Branch for releasing %s (%s) is ready to be pushed and a PR created", version, prepBranch)
		return nil
	}

	// Push branch to remote
	gitRemote := c.String(gitRemoteFlag.Name)
	logrus.Debugf("Pushing branch %s to %s", prepBranch, gitRemote)
	if _, err := git("push", "--force", "--set-upstream", gitRemote, prepBranch); err != nil {
		return fmt.Errorf("error pushing branch %s to remote %s: %w", prepBranch, gitRemote, err)
	}

	// Attempt to create PR for the release prep branch
	remoteURL, err := git("config", "--get", fmt.Sprintf("remote.%s.url", gitRemote))
	if err != nil {
		return fmt.Errorf("error getting remote URL for %s: %w", gitRemote, err)
	}
	githubUser := strings.Split(remoteURL[strings.Index(remoteURL, "git@github.com:")+len("git@github.com:"):strings.LastIndex(remoteURL, ".git")], "/")[0]

	githubOrg := ctx.Value(githubOrgCtxKey).(string)
	githubRepo := ctx.Value(githubRepoCtxKey).(string)
	headBranch := prepBranch
	if githubUser != githubOrg {
		// Forked repo, need to specify head as user:branch
		headBranch = fmt.Sprintf("%s:%s", githubUser, headBranch)
	}
	ctx = context.WithValue(ctx, headBranchCtxKey, prepBranch)
	args := []string{
		"pr", "create", "--fill",
		"--repo", fmt.Sprintf("%s/%s", githubOrg, githubRepo),
		"--base", baseBranch,
		"--head", headBranch,
	}
	if c.String(gitRemoteFlag.Name) == mainRepo {
		// If this is not targeting a fork, add additional details to the PR
		args = append(args, []string{
			// include release team as reviewers
			"--reviewer", "tigera/release-team",
			// set milestone to the version being released
			"--milestone", version,
			// add labels for automation
			"--label", "release-note-not-required,docs-not-required,merge-when-ready,squash-commits,delete-branch",
		}...)
	}
	logrus.WithField("args", strings.Join(args, " ")).Debug("Creating PR for release preparation")
	if pr, err := runCommandInDir(repoRootDir, "hack/bin/gh", args, nil); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create PR: %w", err)
		}
		logrus.Warnf("PR already exists. Find PR at: https://github.com/%s/%s/pulls?q=is%%3Aopen+head%%3A%s", githubOrg, githubRepo, prepBranch)
	} else {
		logrus.WithField("PR", pr).Info("Created PR")
	}

	// Skip milestone management if requested or if using a forked repo
	if c.Bool(skipMilestoneFlag.Name) {
		return nil
	} else if c.String(gitRepoFlag.Name) != mainRepo && !c.Bool(skipRepoCheckFlag.Name) {
		return fmt.Errorf("cannot manage milestones when forked repo (%s); either use the main repo (%s) or set flag to skip repo check", c.String(gitRepoFlag.Name), mainRepo)
	}
	return manageStreamMilestone(ctx, c.String(githubTokenFlag.Name))
})

func excludedComponent(name string) bool {
	for _, pattern := range excludedComponentsPatterns {
		matched, err := regexp.MatchString(pattern, name)
		if err != nil {
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// Update the versions in the given config file located in dir to the specified version
// while preserving comments and ordering in the YAML file.
func updateConfigVersions(dir, relPath, version string) error {
	absPath := filepath.Join(dir, relPath)
	content, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", absPath, err)
	}

	// Use yaml.Node to preserve comments and order when modifying the file
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return fmt.Errorf("error parsing %s: %w", relPath, err)
	}
	var root *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root = doc.Content[0]
	} else {
		root = &doc
	}
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("unexpected YAML structure in %s: root is not a mapping", relPath)
	}
	for i := 0; i < len(root.Content); i += 2 {
		keyNode := root.Content[i]
		valNode := root.Content[i+1]

		// Update title
		if strings.EqualFold(keyNode.Value, "title") {
			valNode.Value = version
			valNode.Tag = "!!str" // ensure it is treated as a string
			continue
		}

		// Update component versions
		if strings.EqualFold(keyNode.Value, "components") && valNode.Kind == yaml.MappingNode {
			for j := 0; j < len(valNode.Content); j += 2 {
				nameNode := valNode.Content[j]
				compNode := valNode.Content[j+1] // should be a mapping node

				// Skip components that are excluded from version updates
				if excludedComponent(nameNode.Value) {
					continue
				}

				// Find "version" node and update its value
				for k := 0; k < len(compNode.Content); k += 2 {
					kNode := compNode.Content[k]
					vNode := compNode.Content[k+1]
					if strings.EqualFold(kNode.Value, "version") {
						vNode.Value = version
						vNode.Tag = "!!str"
						break
					}
				}
			}
		}
	}

	// Write updated YAML preserving node order and original comments.
	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("error opening %s for writing: %w", absPath, err)
	}
	defer func() { _ = file.Close() }()
	enc := yaml.NewEncoder(file)
	defer func() { _ = enc.Close() }()
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("error writing updated versions to %s: %w", absPath, err)
	}
	return nil
}
