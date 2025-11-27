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
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

//go:embed templates/release-notes.md.gotmpl
var releaseNoteTemplate string

// Issue labels
const (
	releaseNoteRequiredLabel = "release-note-required"
	kindLabelPrefix          = "kind/"
	issueKindBugFix          = issueKind("kind/bug")
	issueKindEnhancement     = issueKind("kind/enhancement")
)

// State of issues and milestones
const (
	closedState = "closed"
	allState    = "all"
)

// Context keys
const (
	operatorOrgCtxKey  = "operator-org"
	operatorRepoCtxKey = "operator-repo"
)

type issueKind string

// Command to generate release notes.
// It generates release notes for a new release by collecting release notes from merged PRs
// in the GitHub milestone corresponding to the release version.
var releaseNotesCommand = &cli.Command{
	Name:  "notes",
	Usage: "Generate release notes for a new operator release",
	Flags: []cli.Flag{
		versionFlag,
		skipValidationFlag,
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
	repoInfo := strings.Split(c.String(gitRepoFlag.Name), "/")
	if len(repoInfo) != 2 {
		return nil, fmt.Errorf("invalid git-repo format, expected 'org/repo', got: %s", c.String(gitRepoFlag.Name))
	}
	ctx = context.WithValue(ctx, operatorOrgCtxKey, repoInfo[0])
	ctx = context.WithValue(ctx, operatorRepoCtxKey, repoInfo[1])
	return ctx, nil
})

// Action executed for "release notes" command.
var releaseNotesAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	ver := c.String(versionFlag.Name)
	logrus.WithField("version", ver).Info("Generating release notes")

	release := &Release{
		Org:      ctx.Value(operatorOrgCtxKey).(string),
		Repo:     ctx.Value(operatorRepoCtxKey).(string),
		Version:  ver,
		Token:    c.String(githubTokenFlag.Name),
		Validate: !c.Bool(skipValidationFlag.Name),
	}
	// get root directory of operator git repo
	repoRootDir, err := runCommand("git", []string{"rev-parse", "--show-toplevel"}, nil)
	if err != nil {
		return fmt.Errorf("error getting git root directory: %s", err)
	}
	return release.GenerateNotes(ctx, repoRootDir, c.Bool(localFlag.Name))
})

type Release struct {
	Org          string
	Repo         string
	Version      string
	Token        string
	Validate     bool
	githubClient *github.Client
}

func (r *Release) setupGitHubClient(ctx context.Context) {
	if r.githubClient != nil {
		return
	}
	r.githubClient = github.NewTokenClient(ctx, r.Token)
}

func (r *Release) GenerateNotes(ctx context.Context, outputDir string, useLocal bool) error {
	var writer io.Writer
	var writeLogger *logrus.Entry
	if outputDir == "" {
		logrus.Warn("No output dir specified, will output release notes to stdout")
		writer = os.Stdout
		writeLogger = logrus.WithField("output", "stdout")
	} else {
		if err := os.MkdirAll(outputDir, os.ModeDir); err != nil {
			logrus.WithError(err).Errorf("Failed to create release notes folder %s", outputDir)
			return err
		}
		f, err := os.Create(fmt.Sprintf("%s/%s-release-notes.md", outputDir, r.Version))
		if err != nil {
			logrus.WithError(err).Errorf("Failed to create release notes file in %s", outputDir)
			return err
		}
		defer func() { _ = f.Close() }()
		writer = f
		writeLogger = logrus.WithField("output", f.Name())
	}
	r.setupGitHubClient(ctx)
	noteData, err := r.collectReleaseNotes(ctx, useLocal)
	if err != nil {
		return fmt.Errorf("error collecting release notes: %s", err)
	}
	tmpl, err := template.New("release-note").Parse(releaseNoteTemplate)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse release note template")
		return err
	}
	writeLogger.Debug("Writing release notes")
	if err := tmpl.Execute(writer, noteData); err != nil {
		logrus.WithError(err).Error("Failed to execute release note template")
		return err
	}
	writeLogger.Info("Review release notes for accuracy and format appropriately")
	logrus.Infof("Visit https://github.com/%s/%s/releases/new?tag=%s to publish", r.Org, r.Repo, r.Version)
	return nil
}

// Get the milestone for this release's version.
func (r *Release) milestone(ctx context.Context) (*github.Milestone, error) {
	opts := &github.MilestoneListOptions{
		State: string(allState),
	}
	for {
		milestones, resp, err := r.githubClient.Issues.ListMilestones(ctx, r.Org, r.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, m := range milestones {
			if m.GetTitle() == r.Version {
				return m, nil
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil, fmt.Errorf("milestone %q not found in %s/%s", r.Version, r.Org, r.Repo)
}

// Get all merged PRs (as issues) with the given milestone number that have the "release-note-required" label.
func (r *Release) releaseNoteIssues(ctx context.Context, milestoneNumber int) ([]*github.Issue, error) {
	relIssues := []*github.Issue{}
	opts := &github.IssueListByRepoOptions{
		Milestone: strconv.Itoa(milestoneNumber),
		State:     string(allState),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
		Labels: []string{releaseNoteRequiredLabel},
	}
	for {
		issues, resp, err := r.githubClient.Issues.ListByRepo(ctx, r.Org, r.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, issue := range issues {
			// Only include issues that are PRs and have been merged.
			if issue.IsPullRequest() {
				pr, _, err := r.githubClient.PullRequests.Get(ctx, r.Org, r.Repo, issue.GetNumber())
				if err != nil {
					return nil, err
				}
				if pr.Merged != nil && *pr.Merged {
					relIssues = append(relIssues, issue)
				}
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return relIssues, nil
}

func determineIssueKind(issue *github.Issue) issueKind {
	for _, label := range issue.Labels {
		if strings.HasPrefix(label.GetName(), kindLabelPrefix) {
			return issueKind(label.GetName())
		}
	}
	return issueKind("other")
}

func extractReleaseNoteFromIssue(issue *github.Issue) []string {
	body := issue.GetBody()
	pattern := "\\`\\`\\`release-note(?s)(.*?)\\`\\`\\`"
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		logrus.WithField("issue", issue.GetNumber()).Warn("No release note found in issue body, using issue title instead")
		return []string{issue.GetTitle()}
	}
	logrus.WithFields(logrus.Fields{
		"issue":   issue.GetNumber(),
		"matches": matches,
	}).Debug("Found release note in issue body")
	var notes []string
	for _, match := range matches {
		if len(match) < 2 {
			logrus.WithField("issue", issue.GetNumber()).Warn("No release note content found in matched block")
			continue
		}
		for _, m := range match[1:] {
			for _, line := range strings.Split(m, "\n") {
				trimmedLine := strings.TrimSpace(line)
				if trimmedLine == "TBD" {
					logrus.WithField("issue", issue.GetNumber()).Warn("Release note marked as TBD, not including in release notes")
					continue
				}
				if trimmedLine != "" {
					notes = append(notes, trimmedLine)
				}
			}
		}
	}
	if len(notes) == 0 {
		logrus.WithField("issue", issue.GetNumber()).Warn("No release note content found after processing matched block, using issue title instead")
		return []string{issue.GetTitle()}
	}
	return notes
}

// Gather release notes for this release's milestone.
// A release note is gathered from all merged PRs in the milestone that have the "release-note-required" label.
func (r *Release) collectReleaseNotes(ctx context.Context, local bool) (*ReleaseNoteData, error) {
	data := &ReleaseNoteData{
		Date: time.Now().Format("02 Jan 2006"),
	}
	dir, err := gitDir()
	if err != nil {
		return data, fmt.Errorf("error getting git directory: %s", err)
	}
	versions, err := calicoVersions(dir, r.Version, local)
	if err != nil {
		return data, fmt.Errorf("error retrieving release versions: %s", err)
	}
	data.Versions = versions

	log := logrus.WithField("org", r.Org).WithField("repo", r.Repo).WithField("version", r.Version)
	milestone, err := r.milestone(ctx)
	if err != nil {
		return data, err
	}
	log = log.WithField("milestone", milestone.GetTitle())
	if milestone.GetState() != string(closedState) {
		if r.Validate {
			return data, fmt.Errorf("milestone %q is not closed", milestone.GetTitle())
		}
		log.Warnf("Milestone %q is not closed", milestone.GetTitle())
	}
	log.Debug("Collecting release notes from issues and PRs")
	issues, err := r.releaseNoteIssues(ctx, milestone.GetNumber())
	if err != nil {
		return data, err
	}

	if len(issues) == 0 {
		log.Warnf("No merged PRs found with %q label", releaseNoteRequiredLabel)
		return data, nil
	}

	for _, issue := range issues {
		logrus.WithField("issue", issue.GetNumber()).Debug("Processing release note issue")
		kind := determineIssueKind(issue)
		notes := extractReleaseNoteFromIssue(issue)

		for _, note := range notes {
			switch kind {
			case issueKindBugFix:
				data.BugFixes = append(data.BugFixes, ReleaseNoteItem{
					ID:     issue.GetNumber(),
					Note:   note,
					URL:    issue.GetHTMLURL(),
					Author: issue.GetUser().GetLogin(),
				})
			case issueKindEnhancement:
				data.Enhancements = append(data.Enhancements, ReleaseNoteItem{
					ID:     issue.GetNumber(),
					Note:   note,
					URL:    issue.GetHTMLURL(),
					Author: issue.GetUser().GetLogin(),
				})
			default:
				data.OtherChanges = append(data.OtherChanges, ReleaseNoteItem{
					ID:     issue.GetNumber(),
					Note:   note,
					URL:    issue.GetHTMLURL(),
					Author: issue.GetUser().GetLogin(),
				})
			}
		}
	}

	return data, nil
}

// ReleaseNoteItem represents a single release note extracted from an issue or PR.
type ReleaseNoteItem struct {
	ID     int    // Issue or PR number
	Note   string // The text of the release note
	URL    string // The URL to the issue or PR
	Author string // The author of the issue or PR
}

func (r ReleaseNoteItem) String() string {
	return fmt.Sprintf("%s [#%d](%s) (@%s)", r.Note, r.ID, r.URL, r.Author)
}

// ReleaseNoteData holds categorized release notes for a release.
type ReleaseNoteData struct {
	Date         string
	Enhancements []ReleaseNoteItem
	BugFixes     []ReleaseNoteItem
	OtherChanges []ReleaseNoteItem
	Versions     map[string]string // Calico and Enterprise versions
}

type CalicoVersion struct {
	Title string `yaml:"title"`
}

// Retrieves the Calico and Calico Enterprise versions included in this release.
func calicoVersions(rootDir, operatorVersion string, local bool) (map[string]string, error) {
	versions := make(map[string]string)

	if local && rootDir == "" {
		return versions, fmt.Errorf("rootDir must be specified when using local flag")
	} else if !local {
		rootDir = filepath.Join(os.TempDir(), fmt.Sprintf("operator-%s", operatorVersion))
		err := os.MkdirAll(filepath.Join(rootDir, configDir), os.ModePerm)
		if err != nil {
			return versions, fmt.Errorf("error creating config directory: %s", err)
		}
		defer func() {
			_ = os.RemoveAll(rootDir)
		}()
		if err := retrieveBaseVersionConfig(operatorVersion, rootDir); err != nil {
			return versions, fmt.Errorf("error retrieving version config: %s", err)
		}
	}

	calicoVer, err := retrieveVersion(rootDir, calicoConfig)
	if err != nil {
		return versions, fmt.Errorf("error retrieving Calico version: %s", err)
	}
	if isReleaseVersion, err := isReleaseVersionFormat(calicoVer); err == nil && isReleaseVersion {
		versions["Calico"] = calicoVer
	} else {
		return versions, fmt.Errorf("Calico version is not a valid release version: %s", err)
	}
	enterpriseVer, err := retrieveVersion(rootDir, enterpriseConfig)
	if err != nil {
		return versions, fmt.Errorf("error retrieving Enterprise version: %s", err)
	}
	if isReleaseVersion, err := isEnterpriseReleaseVersionFormat(enterpriseVer); err == nil && isReleaseVersion {
		versions["Calico Enterprise"] = enterpriseVer
	}
	return versions, nil
}

func isEnterpriseReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(enterpriseReleaseFormat)
	if err != nil {
		return false, fmt.Errorf("error compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

func retrieveVersion(dir, filePath string) (string, error) {
	fullPath := fmt.Sprintf("%s/%s", dir, filePath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("error reading version file %s: %w", fullPath, err)
	}
	var version CalicoVersion
	if err := yaml.Unmarshal(data, &version); err != nil {
		return "", fmt.Errorf("error unmarshaling version file %s: %w", fullPath, err)
	}
	return version.Title, nil
}
