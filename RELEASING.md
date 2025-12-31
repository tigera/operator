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

Checkout the branch from which you want to release. Ensure that you are using the correct
operator version for the version of Calico or Enterprise that you are releasing. If in doubt,
check [the releases page](https://github.com/tigera/operator/releases) to find the most
recent Operator release for your Calico or Enterprise minor version.

Run the following command:

```sh
make release-prep VERSION=<OPERATOR_VERSION> CALICO_VERSION=<CALICO_VERSION> ENTERPRISE_VERSION=<ENTERPRISE_VERSION>
```

The command does the following:

- It updates the image version and the title field with the appropriate versions in the
format `vX.Y.Z` for each of the following files:
  1. `config/calico_versions.yml` (Calico OSS version)
  2. `config/enterprise_versions.yml` (Calico Enterprise version)

- It updates the registry reference to `quay.io` from `gcr.io` in the following files:

  1. `TigeraRegistry` in `pkg/components/images.go`

- It ensures `make gen-versions` is run and the resulting updates committed.
- It creates a PR with all the changes
- It manages the milestones on GitHub for the release stream associated with the new release,
  which involves creating a new milestone for the next patch version and closing the current milestone
  for the release version. All open issues and pull requests associated with the current milestone
  are moved to the new milestone.

Go to the PR created and it is reviewed and merged.

## Releasing

Once the PR from [the previous step](#preparing-for-the-release) is merged, follow these steps to create the release:

1. Merge your PR to the release branch

1. Create a git tag `<tag>` for the new commit on the release branch and push it:

    ```sh
    git tag <tag> # e.g git tag v1.30.2
    git push <remote> <tag> # e.g git push origin v1.30.2
    ```

1. Log in to semaphore and run the [release task](https://tigera.semaphoreci.com/projects/operator/schedulers/fcc7fc6c-fb81-4a07-b312-138befbeb111).

1. Once the semaphore run is done, go to [releases](https://github.com/tigera/operator/releases) and edit the draft release for the release tag

1. Publish the release.

    > NOTE: Only mark this release as latest if it is the highest released version

## Updates for new Calico CRDs

(TODO: We need to be able to detect new CRDs and do this automatically)

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-bundle/get-manifests.sh` and `config/manifests/bases/tigera-operator.clusterserviceversion.yaml`.
