# Releasing the operator

## Preparing a new release branch

For a major or minor release, you will need to create a new
`release-vX.Y` branch based on the target minor version.

## Preparing for the release

Review the milestone for this release and ensure it is accurate. https://github.com/tigera/operator/milestones

## Updating versions

Checkout the branch from which you want to release. Ensure that you are using the correct
operator version for the version of Calico or Calient that you are releasing. If in doubt,
check [the releases page](https://github.com/tigera/operator/releases) to find the most
recent Operator release for your Calico or Calient minor version.

Update the image versions and the title field with the appropriate versions in the
format `vX.Y.Z` for each of the following files:

1. `config/calico_versions.yml` (Calico OSS version)
2. `config/enterprise_versions.yml` (Calico Enterprise version)
3. `config/common_versions.yaml` (components common to both)

(When updating versions for enterprise, if necessary also update
the `TigeraRegistry` field in `pkg/components/images.go`.)

Then ensure `make gen-versions` has been ran and the resulting updates have been committed.

Make sure the branch is in a good state: 

1. Update any pins in go.mod
2. Create a PR for all of the local changes (versions updates, gen-versions, etc)
3. Ensure tests pass

You should have no local changes and tests should be passing.

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

1. Go to https://github.com/tigera/operator/milestones and create any new milestones that should exist (e.g., next patch release)

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
