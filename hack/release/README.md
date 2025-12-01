# release

`release` is a tool designed to streamline the process of creating and releasing a new operator version.

- [release](#release)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Commands](#commands)
    - [release prep](#release-prep)
      - [Examples](#examples)
    - [release notes](#release-notes)
      - [Examples](#examples-1)
    - [release from](#release-from)
      - [Examples](#examples-2)

## Installation

To install `release`, use the following command:

```bash
make hack/bin/release
```

## Usage

To start, familarize yourself with the tool

```sh
release --help
```

## Commands

### release prep

This command prepares the repo for a new release.
This typically involves updating the versions config files, image registry for the product if applicable,
and re-generating any generated files.
All the changes are committed to a new branch, which is then pushed to the remote
and a pull request is created against the release branch for review.
Finally, it manages the milestones on GitHub for the release stream associated with the new release,
which involves creating a new milestone for the next patch version and closing the current milestone
for the release version. All open issues and pull requests associated with the current milestone
are moved to the new milestone.

  > [!NOTE]
  > At least one of Calico or Calico Enterprise version must be specified.

To prepare for a new release, use the following command:

```sh
release prep --version <new operator version> [--calico-version <calico version> |
--enterprise-version <calico enterprise version>]
```

If the `--local` flag is specified, none of the remote changes will be made i.e.
no branch in the remote repo and no pull request will be created. Also milestones will not be modified on GitHub.

#### Examples

1. To prepare for a new release `v1.36.0` with Calico version `v3.30.0`

    ```sh
    release prep --version v1.36.0 --calico-version v3.30.0
    ```

1. To prepare for a new release `v1.36.0` with Calico Enterprise version `v3.20.0-1.0`

    ```sh
    release prep --version v1.36.0 --enterprise-version v3.20.0-1.0
    ```

1. To prepare for a new release `v1.36.0` with Calico version `v3.30.0`
   and Calico Enterprise version `v3.20.0-1.0` using local changes only

    ```sh
    release prep --version v1.36.0 --calico-version v3.30.0 --enterprise-version v3.20.0-1.0 --local
    ```

### release notes

This command generates release notes for a specific operator version.
To generate release notes, use the following command:

```sh
release notes --version <operator version>
```

The generated releases notes are saved in a markdown file named `<operator version>-release-notes.md`.

The release notes includes the Calico and Calico Enterprise versions included in the operator version.
By default, this is gotten from the versions files corresponding to the product in `config/` directory
in the commit with the tag matching the operator version.

To get the versions file from the local working directory instead of the tagged commit, use the `--local` flag.

#### Examples

1. To generate release notes for operator version `v1.36.0` from the tagged commit

    ```sh
    release notes --version v1.36.0
    ```

1. To generate release notes for operator version `v1.36.0` using the local versions files

    ```sh
    release notes --version v1.36.0 --local
    ```

### release from

This command creates a new operator version based on a previous operator version.
The base operator version must reference either a tag or commit hash in `tigera/operator`.
The new operator version will be built from the current codebase
with updates made to the image list based on the changes passed in.

```sh
release from --base-version <previous operator version> --version <version to release> \
  [--except-calico | --except-calico-enterprise] <image>:<image version>
```

> [!IMPORTANT]
> To publish the newly created operator, use the `--publish` flag
>
> `--publish` will push the operator image to remote repository
> and ONLY create a draft release on the [Releases](https://github.com/tigera/operator/releases) page for release versions (i.e. vX.Y.Z)

#### Examples

1. To create a new operator with an updated `typha` for Calico to a custom registry locally

    ```sh
    release from --base-version v1.36.0-1.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --version v1.36.0-mod-typha \
    --except-calico typha:v3.30.0-0.dev-353-ge0bc56c0d646 --registry quay.io --image my-namespace/tigera-operator
    ```

1. To create a new operator with an updated `typha` for Calico to a custom registry

    ```sh
    release from --base-version v1.36.0-1.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --version v1.36.0-mod-typha \
    --except-calico typha:v3.30.0-0.dev-353-ge0bc56c0d646 --registry quay.io --image my-namespace/tigera-operator --publish
    ```

1. To create a new operator release `v1.36.3` that has almost all the same images as `v1.36.2`
    with the exception of Enterprise `linseed` component using `v3.20.0-2.2` locally.

    > [!WARNING]
    > This assumes that user has push access to [`tigera/operator`](https://github.com/tigera/operator)

    ```sh
    release from --base-version v1.36.2 --version v1.36.3 \
      --except-calico-enterprise linseed:v3.20.0-2.2
    ```

1. To create a new operator release `v1.36.3` that has almost all the same images as `v1.36.2`
    with the exception of Enterprise `linseed` component using `v3.20.0-2.2`.

    > [!WARNING]
    > This assumes that user has push access to [`tigera/operator`](https://github.com/tigera/operator)
    > and [`quay.io/tigera/operator`](https://quay.io/repository/tigera/operator)

    ```sh
    release from --base-version v1.36.2 --version v1.36.3 \
      --except-calico-enterprise linseed:v3.20.0-2.2 --publish
    ```
