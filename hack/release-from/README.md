# release-from

`release-from` is a tool designed to streamline the process of creating a new operator
using a previously released operator version.

The base operator version must reference either a tag or commit hash in `tigera/operator`

The new operator version will be built from the current codebase
with updates made to the image list based on the changes passed in.

## Installation

To install `release-from`, use the following command:

```bash
make hack/bin/release-from
```

## Usage

To start, familarize yourself with the tool

```sh
release-from --help
```

To create a new release. See [Examples](#examples) below for usage options

```sh
release-from --base-version <previous operator version> --version <version to release> \
  [--except-calico | --except-calico-enterprise] <image>:<image version>
```

> [!IMPORTANT]
> To publish the newly created operator, use the `--publish` flag
>
> `--publish` will push the operator image to remote repository
> and ONLY create a draft release on the [Releases](https://github.com/tigera/operator/releases) page for release versions (i.e. vX.Y.Z)

### Examples

1. To create a new operator with an updated `typha` for Calico to a custom registry locally

    ```sh
    release-from --base-version v1.36.0-1.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --version v1.36.0-mod-typha \
    --except-calico typha:v3.30.0-0.dev-353-ge0bc56c0d646 --registry docker.io --image my-namespace/tigera-operator
    ```

1. To create a new operator with an updated `typha` for Calico to a custom registry

    ```sh
    release-from --base-version v1.36.0-1.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --version v1.36.0-mod-typha \
    --except-calico typha:v3.30.0-0.dev-353-ge0bc56c0d646 --registry docker.io --image my-namespace/tigera-operator --publish
    ```

1. To create a new operator release `v1.36.3` that has almost all the same images as `v1.36.2`
    with the exception of Enterprise `linseed` component using `v3.20.0-2.2` locally.

    > [!WARNING]
    > This assumes that user has push access to [`tigera/operator`](https://github.com/tigera/operator)

    ```sh
    release-from --base-version v1.36.2 --version v1.36.3 \
      --except-calico-enterprise linseed:v3.20.0-2.2
    ```

1. To create a new operator release `v1.36.3` that has almost all the same images as `v1.36.2`
    with the exception of Enterprise `linseed` component using `v3.20.0-2.2`.

    > [!WARNING]
    > This assumes that user has push access to [`tigera/operator`](https://github.com/tigera/operator)
    > and [`quay.io/tigera/operator`](https://quay.io/repository/tigera/operator)

    ```sh
    release-from --base-version v1.36.2 --version v1.36.3 \
      --except-calico-enterprise linseed:v3.20.0-2.2 --publish
    ```
