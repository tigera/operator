# release-from

`release-from` is a tool designed to streamline the process of creating a new operator
using a previously released operator version.

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

To create a new release

```sh
release-from --base-version <previous operator version> --version <version to release> \
  [--except-calico | --except-calico-enterprise] <image>:<image version>
```

> [!IMPORTANT]
> To publish the newly created operator, use the `--publish` flag

### Example

```sh
release-from --base-version v1.36.2 --version v1.36.3 \
  --except-calico-enterprise linseed:v3.20.0-2.2
```
