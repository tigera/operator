# Releasing the operator

## Preparing a new release branch

For a major or minor release, you will need to create a new `release-vX.Y` branch, a dev tag on master,
and a GitHub milestone for the next release. The `create-release-branch` Makefile target automates this:

```sh
make create-release-branch STREAM=vX.Y CALICO_REF=<calico-git-ref> ENTERPRISE_REF=<enterprise-git-ref>
```

This command:

- Creates a `release-vX.Y` branch from master
- Updates `config/calico_versions.yml` and `config/enterprise_versions.yml` to point at the given refs
- Runs `make fix gen-versions-calico gen-versions-enterprise` to regenerate files
- Commits the changes
- Creates a `vX.Y.0-0.dev` tag
- Pushes the branch and tag to the remote

**Flags / environment variables:**

| Env var | Flag | Description |
|---------|------|-------------|
| `STREAM` (required) | `--stream` | Release stream, e.g., `v1.43` |
| `CALICO_REF` (required) | `--calico-ref` | Calico git ref (branch or tag), e.g., `release-v3.32` |
| `ENTERPRISE_REF` (required) | `--enterprise-ref` | Enterprise git ref (branch or tag), e.g., `release-calient-v3.22` |
| `RELEASE_BRANCH_PREFIX` | `--release-branch-prefix` | Branch name prefix (default: `release`) |

For local testing without pushing:

```sh
RELEASE_STREAM=vX.Y CALICO_REF=<ref> ENTERPRISE_REF=<ref> hack/bin/release branch --local
```

After the branch is created, create the next minor release's first milestone at
https://github.com/tigera/operator/milestones (e.g., if `release-v1.43` was created,
create milestone `v1.44.0`).

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

  Pushing the tag should automatically run the release pipeline in CI.

1. Once the CI run is done, go to [releases](https://github.com/tigera/operator/releases) and edit the draft release *as needed* before publishing it.

  > [!IMPORTANT]
  > Only mark this release as latest if it is the highest released version

## Updates for new Calico CRDs

(TODO: We need to be able to detect new CRDs and do this automatically)

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-bundle/get-manifests.sh` and `config/manifests/bases/tigera-operator.clusterserviceversion.yaml`.
