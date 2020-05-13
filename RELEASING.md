# Releasing the operator

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target minor version.

Make sure the appropriate versions have been updated in `config/ee_versions.yaml` or `config/os_versions.yaml`
and then `make gen-versions` has been ran and the resulting updates have been committed. When updating versions
for enterprise, if necessary also update the `TigeraRegistry` field in `pkg/components/images.go`.

Make sure the branch is in a good state, e.g. Update any pins in go.mod, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating release

1. Review the milestone for this release and ensure it is accurate. https://github.com/tigera/operator/milestones

1. Choose a version e.g. `v1.0.1`

1. Create a tag in git

   ```
   git tag <version>
   ```

1. Push the git tag.

1. Log in to semaphore and trigger a build on the tagged commit. Semaphore will build, test, and publish the release.

1. Run the following command to generate release notes for the release

   ```
   GITHUB_TOKEN=<access-token> VERSION=<TAG> ./generate-release-notes.py
   ```

1. Go to https://github.com/tigera/operator/releases and edit the release tag to include the generated release notes, and update the title.

1. Go to https://github.com/tigera/operator/milestones and create any new milestones that should exist (e.g., next patch release)
