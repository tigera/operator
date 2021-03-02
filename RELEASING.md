# Releasing the operator

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target minor version.

Make sure the appropriate versions have been updated in `config/calico_versions.yaml`, `config/enterprise_versions.yaml`
or / and config/common_versions.yaml, make sure both the images have been updated and
the title field has been updated with the release (the format should be `v<Major>.<Minor>.<Patch>`).
Then ensure `make gen-versions` has been ran and the resulting updates have been committed. When updating versions
for enterprise, if necessary also update the `TigeraRegistry` field in `pkg/components/images.go`.

Make sure the branch is in a good state, e.g. Update any pins in go.mod, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating release

1. Review the milestone for this release and ensure it is accurate. https://github.com/tigera/operator/milestones

1. Choose a version e.g. `v1.0.1`

1. Ensure the `title:` field in both config/calico_versions.yaml and config/enterprise_versions.yaml match
   appropriate product release that the operator should install, if not see
   [Preparing for a release](#preparing-for-a-release).

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

1. Close the milestone for this release. https://github.com/tigera/operator/milestones

1. Go to https://github.com/tigera/operator/milestones and create any new milestones that should exist (e.g., next patch release)

## Updates for new Calico CRDs

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-bundle/get-manifests.sh` and `config/manifests/bases/operator.clusterserviceversion.yaml`.

## Publishing a release on RH Catalog

We currently only publish operator releases targeting Calico. If the release targets Calico, continue onto the following steps to generate the
operator bundle for it, and publish the release on the RH Catalog.

1. After the semaphore job in the releasing steps is complete, and images have been tagged and pushed, checkout the release branch containing the released tag.

1. Login to our operator project on connect.redhat.com and publish the operator image on the RH Catalog. This step needs to happen before we generate and submit the operator metadata bundle.

1. Create the operator metadata bundle, using the tag version for VERSION and the version that the release replaces in PREV_VERSION. The versions are semver strings.
   CHANNELS and DEFAULT_CHANNEL should be set to the release stream.
   For example:

   ```
   make bundle VERSION=1.13.1 PREV_VERSION=1.13.0 CHANNELS=release-v1.13 DEFAULT_CHANNEL=release-v1.13
   ```

   This step will create the bundle `bundle/1.13.1`.

1. Login to our operator bundle project on connect.redhat.com

1. Tag and push the operator bundle image to connect.redhat.com

1. Create a PR, adding the new bundle and get it reviewed.

1. Wait until the operator bundle has passed validation tests. Once that has
   happened, publish the new bundle in the UI, and merge the operator PR.

