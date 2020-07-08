# Generating ClusterServiceVersions (CSV) and CSV bundles

This document gives a brief overview of:
- ClusterServiceVersions
- CSV bundles
- operator upgrades via OLM
- the files in this directory that are used to generate them.

## Overview

### CSVs

A ClusterServiceVersion (CSV) is a resource that contains all of the information that the Operator Lifecycle Manager needs to run and manage an operator.
It includes the operator Deployment and RBAC embedded within the CSV. It also includes metadata used to display the operator details
in GUI's like the OpenShift console. Each CSV corresponds to a single version of the operator.

CSV's are generated using the `operator-sdk generate csv` command. Our operator mostly uses the default operator-sdk file and
directory layout. The `operator-sdk generate csv` command uses the manifests in `deploy/` to generate the CSV. For example,
the operator deployment in the CSV is from `deploy/operator.yaml`, the RBAC is from `deploy/role.yaml`, etc.

CSVs are located in `deploy/olm-catalog/tigera-operator/`. Each CSV is in a directory with its version as its name.
Each CSV comes with all of the CRDs specified in the CSV. Every version of the operator that is published on the RH catalog
is represented by these CSVs.

For more details on CSVs, see:
- https://github.com/operator-framework/operator-lifecycle-manager/blob/4197455/Documentation/design/building-your-csv.md
- https://docs.openshift.com/container-platform/4.4/operators/operator_sdk/osdk-generating-csvs.html

### CSV bundles

A bundle is one or more CSVs in "[package manifests](https://sdk.operatorframework.io/docs/olm-integration/generating-a-csv/#package-manifests-format)" format.
A zipped up bundle is uploaded to connect.redhat.com to validate and publish new operator releases.

## Generating CSVs and CSV bundles

To generate a CSV, checkout the git tag that we want to create a CSV for, then generate the CSV
with `make gen-csv VERSION=A.B.C PREV_VERSION=X.Y.Z`.

To generate a CSV bundle, checkout the `master` branch, and run `make gen-bundle`  which copies any generated CSVs
over to `deploy/olm-catalog/`. The make target also generates a new package manifest that specifies the latest published operator version.
(This latest published operator version may or may not already exist on the RH catalog.) The resulting CSV bundle is then committed back to master.

The zipped CSV bundle then uploaded to connect.redhat.com where a validation job is run. Once that job passes, we can publish the bundle.
After the bundle is published, the new operator version will be listed in the RH catalog and in the embedded OperatorHub in OpenShift Console.

### Example

For example, the output of the first step for version=1.3.1 would create this tree:

```
build/_output/bundle/
└── olm-catalog
    └── tigera-operator
        ├── 1.3.1
        │   ├── 02-crd-bgpconfiguration.yaml
        │   ├── 02-crd-bgppeer.yaml
        │   ├── 02-crd-blockaffinity.yaml
        │   ├── 02-crd-clusterinformation.yaml
        │   ├── 02-crd-felixconfiguration.yaml
        │   ├── 02-crd-globalnetworkpolicy.yaml
        │   ├── 02-crd-globalnetworkset.yaml
        │   ├── 02-crd-hostendpoint.yaml
        │   ├── 02-crd-ipamblock.yaml
        │   ├── 02-crd-ipamconfig.yaml
        │   ├── 02-crd-ipamhandle.yaml
        │   ├── 02-crd-ippool.yaml
        │   ├── 02-crd-kubecontrollersconfiguration.yaml
        │   ├── 02-crd-networkpolicy.yaml
        │   ├── 02-crd-networkset.yaml
        │   ├── operator.tigera.io_installations_crd.yaml
        │   ├── operator.tigera.io_tigerastatuses_crd.yaml
        │   └── tigera-operator.v1.3.1.clusterserviceversion.yaml
        └── tigera-operator.package.yaml
```

After running `make gen-bundle` on a branch off of master, we get:

```
deploy/olm-catalog/tigera-operator/
├── 1.3.1
│   ├── 02-crd-bgpconfiguration.yaml
│   ├── 02-crd-bgppeer.yaml
│   ├── 02-crd-blockaffinity.yaml
│   ├── 02-crd-clusterinformation.yaml
│   ├── 02-crd-felixconfiguration.yaml
│   ├── 02-crd-globalnetworkpolicy.yaml
│   ├── 02-crd-globalnetworkset.yaml
│   ├── 02-crd-hostendpoint.yaml
│   ├── 02-crd-ipamblock.yaml
│   ├── 02-crd-ipamconfig.yaml
│   ├── 02-crd-ipamhandle.yaml
│   ├── 02-crd-ippool.yaml
│   ├── 02-crd-kubecontrollersconfiguration.yaml
│   ├── 02-crd-networkpolicy.yaml
│   ├── 02-crd-networkset.yaml
│   ├── operator.tigera.io_installations_crd.yaml
│   ├── operator.tigera.io_tigerastatuses_crd.yaml
│   └── tigera-operator.v1.3.1.clusterserviceversion.yaml
└── tigera-operator.package.yaml
```

The package manifest (`tigera.operator.package.yaml`) points to the latest version in the bundle:

```
channels:
- currentCSV: tigera-operator.v1.3.1
  name: stable
defaultChannel: stable
packageName: tigera-operator
```

Some time later, we have released v1.3.2 of the operator. Going through the same steps results in:

```
deploy/olm-catalog/tigera-operator/
├── 1.3.1
│   ├── 02-crd-bgpconfiguration.yaml
│   ├── 02-crd-bgppeer.yaml
│   ├── 02-crd-blockaffinity.yaml
│   ├── 02-crd-clusterinformation.yaml
│   ├── 02-crd-felixconfiguration.yaml
│   ├── 02-crd-globalnetworkpolicy.yaml
│   ├── 02-crd-globalnetworkset.yaml
│   ├── 02-crd-hostendpoint.yaml
│   ├── 02-crd-ipamblock.yaml
│   ├── 02-crd-ipamconfig.yaml
│   ├── 02-crd-ipamhandle.yaml
│   ├── 02-crd-ippool.yaml
│   ├── 02-crd-kubecontrollersconfiguration.yaml
│   ├── 02-crd-networkpolicy.yaml
│   ├── 02-crd-networkset.yaml
│   ├── operator.tigera.io_installations_crd.yaml
│   ├── operator.tigera.io_tigerastatuses_crd.yaml
│   └── tigera-operator.v1.3.1.clusterserviceversion.yaml
├── 1.3.2
│   ├── 02-crd-bgpconfiguration.yaml
│   ├── 02-crd-bgppeer.yaml
│   ├── 02-crd-blockaffinity.yaml
│   ├── 02-crd-clusterinformation.yaml
│   ├── 02-crd-felixconfiguration.yaml
│   ├── 02-crd-globalnetworkpolicy.yaml
│   ├── 02-crd-globalnetworkset.yaml
│   ├── 02-crd-hostendpoint.yaml
│   ├── 02-crd-ipamblock.yaml
│   ├── 02-crd-ipamconfig.yaml
│   ├── 02-crd-ipamhandle.yaml
│   ├── 02-crd-ippool.yaml
│   ├── 02-crd-kubecontrollersconfiguration.yaml
│   ├── 02-crd-networkpolicy.yaml
│   ├── 02-crd-networkset.yaml
│   ├── operator.tigera.io_installations_crd.yaml
│   ├── operator.tigera.io_tigerastatuses_crd.yaml
│   └── tigera-operator.v1.3.2.clusterserviceversion.yaml
└── tigera-operator.package.yaml
```

The package manifest (`tigera.operator.package.yaml`) points to the latest version in the bundle:

```
channels:
- currentCSV: tigera-operator.v1.3.2
  name: stable
defaultChannel: stable
packageName: tigera-operator
```

## Upgrading the operator via OLM

Each CSV can optionally specify a single operator version that it replaces with the `spec.replaces` field.

![OLM’s graph of available channel updates](https://docs.openshift.com/container-platform/4.2/operators/understanding_olm/olm-understanding-olm.html#olm-upgrades_olm-understanding-olm)
Our operator's CSVs use only a single channel `stable`. Channels are an OLM resource we can use to organize
operator versions. All channels, the "head" version of each channel, and the default channel is in
the package manifest.

An operator's upgrade path will traverse every version in its graph but a CSV can be configured to skip
a range of versions. E.g. if we have v1.3.1, v1.3.2, ... , v1.3.10, we may want the user to upgrade directly
from v1.3.1 to v1.3.10. This is not supported in our current tooling but the method is described [here](https://docs.openshift.com/container-platform/4.2/operators/understanding_olm/olm-understanding-olm.html#olm-upgrades-skipping_olm-understanding-olm).

## Testing a CSV bundle

- Bring up an OpenShift cluster.
- Follow these [instructions](https://github.com/operator-framework/community-operators/blob/master/docs/testing-operators.md#testing-operator-deployment-on-openshift).

## Description of the files

### csv.sh

This script generates a CSV for some operator version. It should be run via the `gen-csv` make target.

### clusterserviceversion.template

The `operator-sdk generate csv` command can use an existing CSV as a starting point.
This file takes advantage of that by providing a base CSV that should be used when generating CSVs.
Whenever we need to update docs URLs, operator description, logo, or any other metadata, we need to edit this file.

### bundle.sh

This script gathers any CSVs generated from `make gen-csv` into `deploy/olm-catalog`, updates the package manifest,
and creates a zip file. It should be run via the `gen-bundle` target.

