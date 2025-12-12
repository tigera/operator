# release

`release` is a tool designed to streamline the process of creating and releasing a new operator.

- [release](#release)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Commands](#commands)
    - [release build](#release-build)
      - [Examples](#examples)
    - [release publish](#release-publish)
    - [Examples](#examples-1)
    - [release prep](#release-prep)
      - [Examples](#examples-2)
    - [release notes](#release-notes)
      - [Examples](#examples-3)
    - [release from](#release-from)
      - [Examples](#examples-4)

## Installation

To install:

```bash
make hack/bin/release
```

  > [!TIP]
  > Add `hack/bin` to your `PATH` to allow running the tool using `release` command.

## Usage

To start, familiarize yourself with the tool

```sh
release --help
```

## Commands

### release build

This command builds the operator image for a specific operator version.

To build the operator image, use the following command:

```sh
release build --version <operator version>
```

For hashrelease, use the `--hashrelease` flag and provide either the Calico or Calico Enterprise version or versions file.

```sh
release build --version <operator version> --hashrelease \
  [--calico-version <calico version> | --calico-versions <path to calico version file> |--enterprise-version <enterprise version> | --enterprise-versions <path to enterprise version file>]
```

#### Examples

1. To build the operator image for operator version `v1.36.0`

    ```sh
    release build --version v1.36.0
    ```

1. To build hashrelease operator image for Calico v3.30

   1. Using Calico versions file

         ```sh
         release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --calico-versions hashrelease-versions.yaml
         ```

   1. Specifying version directly

       ```sh
       release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --calico-version v3.30.0-0.dev-338-gca80474016a5
       ```

1. To build hashrelease operator image for Calico Enterprise v3.22

   1. Using Enterprise versions file

         ```sh
         release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.22.0-calient-0.dev-100-gabcdef123456 --enterprise-versions hashrelease-versions.yaml
         ```

   1. Specifying version directly

       ```sh
       release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.22.0-calient-0.dev-100-gabcdef123456 --enterprise-version v3.22.0-calient-0.dev-100-gabcdef123456
       ```

### release publish

This commands publishes the operator image for a specific operator version to a container registry.

```sh
release publish --version <operator version>
```

For hashrelease, use the `--hashrelease` flag

```sh
release publish --version <operator version> --hashrelease
```

If this is a release version (i.e. vX.Y.Z) and the `--create-github-release` flag is set to true,
it creates a draft release on the [Releases](https://github.com/tigera/operator/releases) page.

### Examples

1. To publish the operator version `v1.36.0`

    ```sh
    release publish --version v1.36.0
    ```

1. To publish the hashrelease operator image for operator version `v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5`

    ```sh
    release publish --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --hashrelease
    ```

1. To publish the operator version `v1.36.0` and create a GitHub release

    ```sh
    release publish --version v1.36.0 --create-github-release
    ```

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

  > [!IMPORTANT]
  > One of Calico or Calico Enterprise version must be specified.

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
