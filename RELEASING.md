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

1. If needed, fetch the latest changes from the repository with `git fetch <remote>`
2. Create a new branch based on the target minor version:

   ```sh
   git checkout <remote>/master -b release-vX.Y
   ```
   
3. Push the new branch to the repository:

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

Review the milestone for this release and ensure it is accurate. https://github.com/tigera/operator/milestones

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

1. Create a git tag for the new commit on the release branch and push it:

```
git tag v1.30.3
git push --tags
```

1. Log in to semaphore and find the new build for the release branch commit, and
   click 'Rerun'. When Semaphore starts the rebuild, it will notice the new tag and
   build and publish an operator release.

## Release notes and milestones

1. Run the following command to generate release notes for the release

   ```
   GITHUB_TOKEN=<access-token> VERSION=<TAG> ./generate-release-notes.py
   ```

1. Go to https://github.com/tigera/operator/releases and edit the release tag to include the generated release notes, and update the title.

1. Close the milestone for this release. https://github.com/tigera/operator/milestones

1. Go to https://github.com/tigera/operator/milestones and create any new milestones that should exist
   - Create the next patch version
   - If a new minor was released (`.0`), also ensure the next minor has been created (this should have already been created as part of [Preparing a new release branch](#preparing-a-new-release-branch))

## Updates for new Calico CRDs

(TODO: We need to be able to detect new CRDs and do this automatically)

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-bundle/get-manifests.sh` and `config/manifests/bases/operator.clusterserviceversion.yaml`.

## Publishing a release on the RH Catalog

(Note: We are not currently publishing to RH Catalog, but we will resume soon. These notes are left here for current and future reference.)

We currently only publish operator releases targeting Calico. If the release targets Calico, continue onto the following steps to generate the
operator bundle for it, and publish the release on the RH Catalog.

Before beginning, ensure that the docs at docs.projectcalico.org for the Calico version this operator release targets is live.

1. After the semaphore job in the releasing steps is complete, and images have been tagged and pushed, checkout the tag you released and create a new branch.

1. Login to our operator project on connect.redhat.com and publish the operator image on the RH Catalog. This step needs to happen before we generate and submit the operator bundle.

1. Create the operator bundle using `make bundle` with the required variables `VERSION`, `PREV_VERSION`, `CHANNELS`, and `DEFAULT_CHANNEL`:

   **Note**: the version strings in `VERSION` and `PREV_VERSION` are semver strings without the v.

   - **VERSION**: this release version. E.g. `1.13.1`
   - **PREV_VERSION**: the latest published bundle version in this release stream. Navigate to the [certified operators production catalog](https://github.com/redhat-openshift-ecosystem/certified-operators/tree/main/operators/tigera-operator) and look for the most recent version from this release branch. E.g., if this release is `v1.24.11` but the most recently published v1.24.x bundle is `1.24.9` then you would use `VERSION=1.24.11` and `PREV_VERSION=1.24.9`. If this release is the first in this release branch, then there is no prior version so set `PREV_VERSION=0.0.0`.
   - **CHANNELS** and **DEFAULT_CHANNEL**: should be set to the release branch of this operator release. E.g., if the operator release tag is `v1.23.5`, then CHANNELS and DEFAULT_CHANNEL should be `release-v1.23`.

   For example:

   ```
   make bundle VERSION=1.13.1 PREV_VERSION=1.13.0 CHANNELS=release-v1.13 DEFAULT_CHANNEL=release-v1.13
   ```

   This step will create the bundle `bundle/1.13.1`.

1. Publish the generated operator bundle following the [Operator Certification CI Pipeline instructions](https://github.com/redhat-openshift-ecosystem/certification-releases/blob/main/4.9/ga/ci-pipeline.md). Bundles are no longer committed in this repository as they are committed in [redhat-openshift-ecosystem/certified-operators](https://github.com/redhat-openshift-ecosystem/certified-operators).
