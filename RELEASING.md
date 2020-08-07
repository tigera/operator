# Releasing the operator

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target minor version.

Make sure the branch is in a good state, e.g. Update any pins in glide.yaml, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating release

1. Choose a version e.g. `v1.0.1`

1. Create a tag in git

   ```
   git tag <version>
   ```

1. Push the git tag.

1. Log in to semaphore and trigger a build on the tagged commit. Semaphore will build, test, and publish the release.

## Updates for new Calico CRDs

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-csv/get-manifests.sh` and `hack/gen-csv/clusterserviceversion.template`.

## Publishing a release on RH Catalog

We currently only publish operator releases targeting Calico. If the release targets Calico, continue onto the following steps to generate the
ClusterServiceVersion for it, and publish the release on the RH Catalog.

1. After the semaphore job in the releasing steps is complete, and images have been tagged and pushed, checkout the tag you released.

1. Create the ClusterServiceVersion (CSV), using the tag version for VERSION and the version that this replaces in PREV_VERSION.
   The versions are semver strings. For example:

   ```
   make gen-csv VERSION=1.3.1 PREV_VERSION=1.3.0
   ```

   This step will create the CSV and copy over its crds into `build/_output/bundle/tigera-operator/$VERSION` which will be used in the next step,
   on master.

3. Checkout `master` and create a new branch.

4. Create the CSV bundle:

   ```
   make gen-bundle
   ```

   This step will add the CSV we generated earlier to `deploy/olm-catalog` and create a zip file in `build/_output/bundle/bundle.zip`.

5. `git add deploy/olm-catalog`, commit the changes, and have the PR reviewed and merged into master.

6. Login to our operator project metadata [submission page](https://connect.redhat.com/project/2072901/operator-metadata) and upload the bundle.zip

7. The metadata validation job takes 1-2 hours if it runs successfully. When it passes, go back to the same submission page and publish the new operator version.
