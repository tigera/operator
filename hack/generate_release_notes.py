#!/usr/bin/env python3
"""Generate release notes for a milestone.

Raises:
  ReleaseNoteError: _description_
"""
import os
import re
import sys
import datetime
import yaml
from github import Github, Auth  # https://github.com/PyGithub/PyGithub
from github.Milestone import Milestone
from github.Issue import Issue
from github.PullRequest import PullRequest

# Validate required environment variables

if GITHUB_TOKEN := os.environ.get("GITHUB_TOKEN"):
    if not GITHUB_TOKEN.startswith("gh"):
        raise ValueError("GITHUB_TOKEN must start with 'gh?_'")
else:
    raise ValueError("GITHUB_TOKEN must be set in the environment")

# Version corresponds to the milestone in the GitHub repository
VERSION = os.environ.get("VERSION")
if VERSION := os.environ.get("VERSION"):
    if not VERSION.startswith("v"):
        raise ValueError("VERSION string must start with 'v'")
else:
    raise ValueError("VERSION must be set in the environment")

# First create a Github instance. Create a token through Github website - provide "repo" auth.
auth = Auth.Token(GITHUB_TOKEN)
g = Github(auth=auth)

# The file where we'll store the release notes.
FILENAME = f"{VERSION}-release-notes.md"


class ReleaseNoteError(Exception):
    """Release note error.

    Args:
      Exception (_type_): _description_
    """


def issues_in_milestone() -> list:
    """Returns a dictionary where the keys are repositories, and the values are
    a list of issues in the repository which match the milestone and
    have a `release-note-required` label.

    Raises:
        ReleaseNoteError: _description_

    Returns:
        list: list of issues
    """
    repo = g.get_repo("tigera/operator")

    # Find the milestone to get the id.
    for m in repo.get_milestones(state="all"):
        if m.title == VERSION:
            print(f"Found matching milestone {m.title}: {m.html_url}")
            milestone: Milestone = m
            break

    milestone: Milestone = milestone  # type: ignore # Fixes "possibly unbound" warnings

    if milestone is None:
        raise RuntimeError(f"Could not file milestone matching version {VERSION}")

    # Ensure the milestone is closed before generating release notes.
    if milestone.state != "closed":
        raise ReleaseNoteError(
            f"milestone {milestone.title} is not closed; please close it first!"
        )
    milestone_issues = repo.get_issues(
        milestone=milestone, state="closed", labels=["release-note-required"]
    )
    # Fetch all of our "issues" as pull requests.
    milestone_prs_list: list[PullRequest] = [issue.as_pull_request() for issue in milestone_issues]

    open_prs = [pr for pr in milestone_prs_list if pr.state == "open"]

    # If there are open issues in the milestone, raise an error.
    if open_prs:
        raise ReleaseNoteError(
            f"{len(open_prs)} PRs are still open, please move them to the next milestone or close them before generating release notes."  # pylint: disable=line-too-long
        )

    # Now we get a list of all merged PRs (i.e. we filter out closed PRs)
    merged_prs = [pr for pr in milestone_prs_list if pr.merged]

    # If we didn't get any merged PRs, we need to print a warning, *BUT*
    # it's possible that there just weren't any PRs merged in this milestone.
    if not merged_prs:
        print("", file=sys.stderr)
        print("WARNING: No merged PRs found in the milestone.", file=sys.stderr)
        print("         Please ensure that the milestone is correct!", file=sys.stderr)

    # Return only the merged PRs
    return merged_prs


def extract_release_notes(issue: Issue) -> list:
    """Take an issue and return the appropriate release notes from that issue as a list.

    Args:
        issue (Issue): _GitHub issue_

    Returns:
        list: Either the release notes from the issue, or the title.
    """
    # Look for a release note section in the body.
    matches: list[str] = []
    if issue.body:
        matches = re.findall(r"```release-note(.*?)```", str(issue.body), re.DOTALL)

    if matches:
        return [m.strip() for m in matches]
    # If no release notes explicitly declared, then use the PR title.
    return [issue.title.strip()]


def kind(issue: Issue) -> str:
    """Get the kind of issue.

    Args:
          issue (Issue): _GitHub issue_

    Returns:
        str: enhancement, bug, or other
    """
    for label in issue.labels:
        if label.name == "kind/enhancement":
            return "enhancement"
        if label.name == "kind/bug":
            return "bug"
    return "other"


def enterprise_feature(issue: Issue) -> bool:
    """Check if the issue is an enterprise feature.

    Args:
        issue (Issue): GitHub issue

    Returns:
        _bool_: True if the issue is an enterprise feature
    """
    for label in issue.labels:
        if label.name == "enterprise":
            return True
    return False


def print_issues_to_file(file, issues: list) -> None:
    """Print issues to a file.

    Args:
        file (TextIOWrapper): file to write to
        issues (list): list of issues
    """
    for issue in issues:
        for note in extract_release_notes(issue):
            if enterprise_feature(issue):
                file.write(
                    f"- [Calico Enterprise] {note} [#{issue.number}]({issue.html_url}) (@{issue.user.login})\n"  # pylint: disable=line-too-long
                )
            else:
                file.write(
                    f"- {note} [#{issue.number}]({issue.html_url}) (@{issue.user.login})\n"
                )
    file.write("\n")


def calico_version() -> str:
    """Get the Calico version.

    Returns:
        str: calico version
    """
    with open("config/calico_versions.yml", encoding="utf-8") as calico_versions:
        v = yaml.safe_load(calico_versions)
    return v["title"]


def enterprise_version() -> str:
    """Get the Calico Enterprise version.

    Returns:
        str: calico enterprise version
    """
    with open("config/enterprise_versions.yml", encoding="utf-8") as enterprise_versions:
        v = yaml.safe_load(enterprise_versions)
    return v["title"]


if __name__ == "__main__":
    # Get the list of issues.
    all_issues = issues_in_milestone()

    # Get date in the right format.
    date = datetime.date.today().strftime("%d %b %Y")

    # Sort issues into groups: enhancement, bugfix, other
    enhancements = []
    bugs = []
    other = []
    for i in all_issues:
        if kind(i) == "enhancement":
            enhancements.append(i)
        if kind(i) == "bug":
            bugs.append(i)
        if kind(i) == "other":
            other.append(i)

    # Write release notes out to a file.
    with open(FILENAME, "w", encoding="utf-8") as f:
        f.write(f"{date}\n\n")

        f.write("#### Included Calico versions\n\n")
        f.write(f"Calico version: {calico_version()}\n")
        f.write(f"Calico Enterprise version: {enterprise_version()}\n\n")

        if len(enhancements) > 0:
            f.write("#### Enhancements\n\n")
            print_issues_to_file(f, enhancements)
        if len(bugs) > 0:
            f.write("#### Bug fixes\n\n")
            print_issues_to_file(f, bugs)
        if len(other) > 0:
            f.write("#### Other changes\n\n")
            print_issues_to_file(f, other)

    print("")
    print("Release notes written to " + FILENAME)
    print("Please review for accuracy, and format appropriately before releasing.")
    print("")
    print(
        f"Visit https://github.com/tigera/operator/releases/new?tag={VERSION}# to publish"
    )
