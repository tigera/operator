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
	"html/template"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/sirupsen/logrus"
)

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

type issueKind string

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

type GithubRelease struct {
	Org          string
	Repo         string
	Version      string
	githubClient *github.Client
	milstone     *github.Milestone
}

func (r *GithubRelease) setupClient(ctx context.Context, token string) error {
	if r.githubClient != nil {
		return nil
	}
	if token == "" {
		return fmt.Errorf("GitHub token is required to create GitHub client")
	}
	r.githubClient = github.NewTokenClient(ctx, token)
	return nil
}

// Get the getMilestone for this release's version.
func (r *GithubRelease) getMilestone(ctx context.Context) (*github.Milestone, error) {
	if r.milstone != nil {
		return r.milstone, nil
	}
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
				r.milstone = m
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

func (r *GithubRelease) GenerateNotes(ctx context.Context, outputDir string, useLocal bool) error {
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

// Get all merged PRs (as issues) with the given milestone number that have the "release-note-required" label.
func (r *GithubRelease) releaseNoteIssues(ctx context.Context) ([]*github.Issue, error) {
	milestone, err := r.getMilestone(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving milestone for version %s: %w", r.Version, err)
	}
	if milestone.GetState() != string(closedState) {
		logrus.WithField("milestone", milestone.GetTitle()).Warn("Milestone is not closed")
	}
	opts := &github.IssueListByRepoOptions{
		Milestone: strconv.Itoa(milestone.GetNumber()),
		State:     string(allState),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
		Labels: []string{releaseNoteRequiredLabel},
	}
	filter := func(issue *github.Issue) bool {
		if !issue.IsPullRequest() {
			return false
		}
		pr, _, err := r.githubClient.PullRequests.Get(ctx, r.Org, r.Repo, issue.GetNumber())
		if err != nil {
			logrus.WithField("issue", issue.GetNumber()).WithError(err).Error("Error retrieving PR for issue")
			return false
		}
		return pr.Merged != nil && *pr.Merged
	}
	relIssues, err := githubIssues(ctx, r.githubClient, r.Org, r.Repo, opts, filter)
	if err != nil {
		return nil, fmt.Errorf("error retrieving release note issues: %w", err)
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
func (r *GithubRelease) collectReleaseNotes(ctx context.Context, local bool) (*ReleaseNoteData, error) {
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
	issues, err := r.releaseNoteIssues(ctx)
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

func githubIssues(ctx context.Context, client *github.Client, org, repo string, opts *github.IssueListByRepoOptions, filter func(*github.Issue) bool) ([]*github.Issue, error) {
	issues := []*github.Issue{}
	for {
		pageIssues, resp, err := client.Issues.ListByRepo(ctx, org, repo, opts)
		if err != nil {
			return nil, err
		}
		for _, issue := range pageIssues {
			if filter == nil || filter(issue) {
				issues = append(issues, issue)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return issues, nil
}

