# Releasing the operator

## Preparing a new release branch

For a major or minor release, you will need to create:

- A new `release-vX.Y` branch based on the target minor version.  We always do releases from a release
  branch, not from master.
- An empty commit on the master branch, tagged with the "dev" version for the next minor release.
  This ensures that `git describe --tags` (which is used to generate versions for CI builds) will
  produce a version that "makes sense" for master commits after the release branch is created.
- A new GitHub milestone for the next minor release.  This ensures that new PRs get auto-added to
  the correct milestone.

To create a new release branch:

1. If needed, fetch the latest changes from the repository remote `<remote>`:

    ```sh
    git fetch <remote>
    ```

1. Create a new branch based on the target minor version:

   ```sh
   git checkout <remote>/master -b release-vX.Y
   ```

1. Push the new branch to the repository:

   ```sh
   git push <remote> release-vX.Y
   ```

To create an empty commit and tag on master; run the following commands.  This will push directly to master,
bypassing the normal PR process.  This is important to make sure that the tag is directly on the master branch.
We create an empty commit because, when the release branch is created, it shares its commit history with master.
So, if we tagged the tip of master, we'd also be tagging the tip of the release branch, which would give
incorrect results for `git describe --tags` on the release branch.

   ```sh
   git checkout <remote>/master
   git commit --allow-empty -m "Start development on vX.Y"  # Where vX.Y is the next minor version
   git tag vX.Y.0-0.dev
   git push <remote> HEAD:master   # Note: if someone updates master before you push, delete the tag and start over from the new tip of master.
   git push <remote> vX.Y.0-0.dev
   ```

*Note* that the tag should have the exact format `vX.Y.0-0.dev` where `X.Y` is the next minor version.
The `-0.dev` suffix was chosen to produce a semver-compliant version that is less than the
first release version for the new minor version.

Finally, create the next minor release's first milestone at https://github.com/tigera/operator/milestones.
This would mean if the branch release-v1.30 is being created, then the milestone v1.31.0 should be created too.
This ensures that new PRs against master will be automatically given the correct tag.

## Preparing for the release

- Create any new milestones that should exist
  - Create the next patch version
  - If a new minor was released (`.0`), also ensure the next minor has been created (this should have already been created as part of [Preparing a new release branch](#preparing-a-new-release-branch))
- Review the milestone for this release and ensure it is accurate. https://github.com/tigera/operator/milestones
  - Move any open PRs to a new milestone (*likely* the newly created one)
  - Close the milestone for the release

## Updating versions

Checkout the branch from which you want to release. Ensure that you are using the correct
operator version for the version of Calico or Calient that you are releasing. If in doubt,
check [the releases page](https://github.com/tigera/operator/releases) to find the most
recent Operator release for your Calico or Calient minor version.

Make sure pins are updated in `go.mod`

Run the following command:

```sh
make release-prep GIT_PR_BRANCH_BASE=<RELEASE_BRANCH> GIT_REPO_SLUG=tigera/operator CONFIRM=true \
  VERSION=<OPERATOR_VERSION> CALICO_VERSION=<CALICO_VERSION> CALICO_ENTERPRISE_VERSION=<CALICO_ENTERPRISE_VERSION> COMMON_VERSION=<COMMON_VERSION>
```

The command does the following:

- It updates the image version and the title field with the appropriate versions in the
format `vX.Y.Z` for each of the following files:
  1. `config/calico_versions.yml` (Calico OSS version)
  2. `config/enterprise_versions.yml` (Calico Enterprise version)

- It updates the registry reference to `quay.io` from `gcr.io` for each of the following files:

  1. `TigeraRegistry` in `pkg/components/images.go`
  2. `defaultEnterpriseRegistry` in `hack/gen-versions/main.go`

- It ensures `make gen-versions` is run and the resulting updates committed.
- It creates a PR with all the changes

Go to the PR created and:

1. Ensure tests pass
2. Update the labels in the PR  to include `docs-not-required` and `release-note-not-required`

## Releasing

1. Merge your PR to the release branch

1. Create a git tag `<tag>` for the new commit on the release branch and push it:

    ```sh
    git tag <tag> # e.g git tag v1.30.2
    git push <remote> <tag> # e.g git push origin v1.30.2
    ```

1. Log in to semaphore and find the new build for the release branch commit, and
   click 'Rerun'. When Semaphore starts the rebuild, it will notice the new tag and
   build and publish an operator release.

1. Go to [releases](https://github.com/tigera/operator/releases) and edit the draft release for the release tag

1. Publish the release.

    > NOTE: Only mark this release as latest if it is the highest released version

## Updates for new Calico CRDs

(TODO: We need to be able to detect new CRDs and do this automatically)

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-bundle/get-manifests.sh` and `config/manifests/bases/operator.clusterserviceversion.yaml`.
