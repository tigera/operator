#!/usr/bin/env python3
"""Generate release notes for a milestone.

Raises:
  ReleaseNoteError: _description_
"""
import os
import re
import datetime
import yaml
from github import Github, Auth, Issue  # https://github.com/PyGithub/PyGithub

# Validate required environment variables
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
assert GITHUB_TOKEN, "GITHUB_TOKEN must be set"
# Version corresponds to the milestone in the GitHub repository
VERSION = os.environ.get("VERSION")
assert os.environ.get("VERSION"), "VERSION must be set"
assert VERSION.startswith("v"), "VERSION must start with 'v'"

# First create a Github instance. Create a token through Github website - provide "repo" auth.
auth = Auth.Token(os.environ.get("GITHUB_TOKEN"))
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

    # Find the milestone. This finds all open milestones.
    milestones = repo.get_milestones()
    for m in milestones:
        if m.title == VERSION:
            # Found the milestone in this repo - look for issues (but only
            # ones that have been closed!)
            print(f"  found milestone {m.title}")
            milestone_issues = repo.get_issues(
                milestone=m, state="closed", labels=["release-note-required"]
            )
            issues = []
            for issue in milestone_issues:
                pr = issue.as_pull_request()
                if pr.merged:
                    # Filter out PRs which are closed but not merged.
                    issues.append(issue)
                elif pr.state == "open":
                    print(f"WARNING: {pr.number} is still open, remove from milestione... skipping")
            if len(issues) == 0:
                raise ReleaseNoteError(f"no issues found for milestone {m.title}")
            return issues


def extract_release_notes(issue: Issue) -> list:
    """Take an issue and return the appropriate release notes from that issue as a list.

    Args:
        issue (Issue): _GitHub issue_

    Returns:
        list: Either the release notes from the issue, or the title.
    """
    # Look for a release note section in the body.
    matches = None
    if issue.body:
        matches = re.findall(r"```release-note(.*?)```", str(issue.body), re.DOTALL)

    if matches:
        return [m.strip() for m in matches]
    else:
        # If no release notes explicitly declared, then use the PR title.
        return [issue.title.strip()]


def kind(issue: Issue) -> str:
    """Get the kind of issue.

    Args:
          issue (Issue): _GitHub issue_

    Returns:
        str: enhancement, bug, or other
    """
    for l in issue.labels:
        if l.name == "kind/enhancement":
            return "enhancement"
        if l.name == "kind/bug":
            return "bug"
    return "other"


def enterprise_feature(issue: Issue) -> bool:
    """Check if the issue is an enterprise feature.

    Args:
        issue (Issue): GitHub issue

    Returns:
        _bool_: True if the issue is an enterprise feature
    """
    for l in issue.labels:
        if l.name == "enterprise":
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
                    f" - [Calico Enterprise] {note} [#{issue.number}]({issue.html_url}) (@{issue.user.login})\n"  # pylint: disable=line-too-long
                )
            else:
                file.write(
                    f" - {note} [#{issue.number}]({issue.html_url}) (@{issue.user.login})\n"
                )
    file.write("\n")


def calico_version() -> str:
    """Get the Calico version.

    Returns:
        str: calico version
    """
    v = yaml.safe_load(open("config/calico_versions.yml", "r", encoding="utf-8"))
    return v["title"]


def enterprise_version() -> str:
    """Get the Calico Enterprise version.

    Returns:
        str: calico enterprise version
    """
    v = yaml.safe_load(open("config/enterprise_versions.yml", "r", encoding="utf-8"))
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
