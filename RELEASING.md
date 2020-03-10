# Releasing the operator

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target minor version.

Make sure the appropriate versions have been updated in `config/ee_versions.yaml` or `config/os_versions.yaml`
and then `make gen-versions` has been ran and the resulting updates have been committed.

Make sure the branch is in a good state, e.g. Update any pins in go.mod, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating release

1. Choose a version e.g. `v1.0.1`

1. Create a tag in git

   ```
   git tag <version>
   ```

1. Push the git tag.

1. Log in to semaphore and trigger a build on the tagged commit. Semaphore will build, test, and publish the release.

1. Create a github release and add notes for the changes that have gone in since the previous tag. Include the versions
   of Calico and Enterprise components that are in the release.
