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

1. Push the git tag. Semaphore will build the release for you.
