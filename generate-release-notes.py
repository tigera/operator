#!/usr/bin/env python3
from github import Github  # https://github.com/PyGithub/PyGithub
import yaml
import os
import re
import io
import datetime

# First create a Github instance. Create a token through Github website - provide "repo" auth.
g = Github(os.environ.get('GITHUB_TOKEN'))

# The milestone to generate notes for.
assert os.environ.get('VERSION')
MILESTONE=os.environ.get('VERSION')

# The file where we'll store the release notes.
FILENAME="%s-release-notes.md" % MILESTONE

# Returns a dictionary where the keys are repositories, and the values are
# a list of issues in the repository which match the milestone and
# have a `release-note-required` label.
def issues_in_milestone():
    repo = g.get_repo("tigera/operator")

    # Find the milestone. This finds all open milestones.
    milestones = repo.get_milestones()
    for m in milestones:
        if m.title == MILESTONE:
            # Found the milestone in this repo - look for issues (but only
            # ones that have been closed!)
            issues = []
            for i in repo.get_issues(milestone=m, state="closed", labels=['release-note-required']):
                pr = i.as_pull_request()
                if pr.merged:
                    # Filter out PRs which are closed but not merged.
                    issues.append(i)
            return issues
    raise Exception("Unable to find issues in milestone")

# Takes an issue and returns the appropriate release notes from that
# issue as a list.  If it has a release-note section defined, that is used.
# If not, then it simply returns the title.
def extract_release_notes(issue):
    # Look for a release note section in the body.
    matches = None
    if issue.body:
        matches = re.findall(r'```release-note(.*?)```', issue.body, re.DOTALL)

    if matches:
        return [m.strip() for m in matches]
    else:
        # If no release notes explicitly declared, then use the PR title.
        return [issue.title.strip()]

def kind(issue):
    for l in issue.labels:
        if l.name == "kind/enhancement":
            return "enhancement"
        if l.name == "kind/bug":
            return "bug"
    return "other"

def enterprise_feature(issue):
    for l in issue.labels:
        if l.name == "enterprise":
            return True
    return False

def print_issues_to_file(f, issues):
    for i in issues:
        for note in extract_release_notes(i):
            if enterprise_feature(i):
                f.write(" - [Calico Enterprise] %s [#%d](%s) (@%s)\n" % (note, i.number, i.html_url, i.user.login))
            else:
                f.write(" - %s [#%d](%s) (@%s)\n" % (note, i.number, i.html_url, i.user.login))
    f.write(u"\n")

def calico_version():
    v = yaml.safe_load(open('config/calico_versions.yml', 'r'))
    return v['title']

def enterprise_version():
    v = yaml.safe_load(open('config/enterprise_versions.yml', 'r'))
    return v['title']

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
    with io.open(FILENAME, "w", encoding='utf-8') as f:
        f.write(u"%s\n\n" % date)

        f.write(u"#### Included Calico versions\n\n")
        f.write(u"Calico version: %s\n" % calico_version())
        f.write(u"Calico Enterprise version: %s\n\n" % enterprise_version())

        if len(enhancements) > 0:
            f.write(u"#### Enhancements\n\n")
            print_issues_to_file(f, enhancements)
        if len(bugs) > 0:
            f.write(u"#### Bug fixes\n\n")
            print_issues_to_file(f, bugs)
        if len(other) > 0:
            f.write(u"#### Other changes\n\n")
            print_issues_to_file(f, other)

    print("")
    print("Release notes written to " + FILENAME)
    print("Please review for accuracy, and format appropriately before releasing.")
    print("")
    print("Visit https://github.com/tigera/operator/releases/edit/%s# to publish" % MILESTONE)
