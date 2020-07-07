#!/bin/bash
#
# This script generates a ClusterServiceVersion with its corresponding CRDs in
# "package manifests" format.
#
# For example, running this script with VERSION=1.6.2 results in this tree:
#
# build/_output/bundle/
# └── olm-catalog
#     └── tigera-operator
#         ├── 1.6.2
#         │   ├── 02-crd-bgpconfiguration.yaml
#         │   ├── 02-crd-bgppeer.yaml
#         │   ├── 02-crd-blockaffinity.yaml
#         │   ├── 02-crd-clusterinformation.yaml
#         │   ├── 02-crd-felixconfiguration.yaml
#         │   ├── 02-crd-globalnetworkpolicy.yaml
#         │   ├── 02-crd-globalnetworkset.yaml
#         │   ├── 02-crd-hostendpoint.yaml
#         │   ├── 02-crd-ipamblock.yaml
#         │   ├── 02-crd-ipamconfig.yaml
#         │   ├── 02-crd-ipamhandle.yaml
#         │   ├── 02-crd-ippool.yaml
#         │   ├── 02-crd-kubecontrollersconfiguration.yaml
#         │   ├── 02-crd-networkpolicy.yaml
#         │   ├── 02-crd-networkset.yaml
#         │   ├── operator.tigera.io_installations_crd.yaml
#         │   ├── operator.tigera.io_tigerastatuses_crd.yaml
#         │   └── tigera-operator.v1.6.2.clusterserviceversion.yaml
#         └── tigera-operator.package.yaml
set -e
set -x

if [[ -z "${VERSION}" ]]; then
	echo VERSION is undefined - run with vars VERSION=X.Y.Z PREV_VERSION=D.E.F
	exit 1
fi
if [[ -z "${PREV_VERSION}" ]]; then
	echo PREV_VERSION is undefined - run with vars VERSION=X.Y.Z PREV_VERSION=D.E.F
	exit 1
fi

# The version of the operator to publish.
VERSION="${VERSION}"

# The version of the operator that VERSION replaces. If this version does not
# replace a version, use 0.0.0
PREV_VERSION="${PREV_VERSION}"

# This is the top-level directory of this script's artifacts.
OUTPUT_DIR=build/_output/bundle

# This directory serves two purposes.
# - it's the source directory of CRDs that we want in the resulting CSV package.
# - it's the output directory of the CSV output from the 'operator-sdk generate csv' command.
CSV_DIR=${OUTPUT_DIR}/olm-catalog/tigera-operator/${VERSION}

CSV=${CSV_DIR}/tigera-operator.v${VERSION}.clusterserviceversion.yaml

# Create the CSV output directory tree.
mkdir -p ${CSV_DIR}

# Copy over the required CRDs.
cp deploy/crds/operator.tigera.io_installations_crd.yaml ${CSV_DIR}
cp deploy/crds/operator.tigera.io_tigerastatuses_crd.yaml ${CSV_DIR}
cp deploy/crds/calico/* ${CSV_DIR}

# Copy over the CSV template that will be used as a base CSV. This base CSV has
# existing values we want for all versions of the tigera-operator.
# The param '--make-manifests=false' is required for the CSV template to be used.
cp hack/gen-csv/clusterserviceversion.template ${CSV}

# Finally, generate the ClusterServiceVersion (CSV). The resulting artifacts will be in ${CSV_DIR}.
hack/bin/operator-sdk generate csv \
  --operator-name tigera-operator \
  --csv-channel stable \
  --csv-version ${VERSION} \
  --crd-dir ${CSV_DIR} \
  --apis-dir pkg/apis/operator/v1/ \
  --make-manifests=false \
  --verbose \
  --interactive=false \
  --output-dir=${OUTPUT_DIR}

OPERATOR_IMAGE=quay.io/tigera/operator:v${VERSION}

# Pull the image so we can inspect it.
docker pull ${OPERATOR_IMAGE}

# Set the operator image container image and creation timestamp annotations.
yq write -i ${CSV} metadata.annotations.containerImage ${OPERATOR_IMAGE}
TIMESTAMP=$(docker image inspect ${OPERATOR_IMAGE} | jq -r .[0].Created)
yq write -i ${CSV} metadata.annotations.createdAt ${TIMESTAMP}

# Get the digest for the image. 'docker inspect' returns output like the example
# below. RepoDigests may have more than one entry so we need to filter.
# [
#     {
#         "Id": "sha256:34a1114040c03830da0a8d57f8d999deba26d8e31bda353aed201a375f68870b",
#         "RepoTags": [
#             "quay.io/tigera/operator:v1.3.1",
#             "..."
#         ],
#         "RepoDigests": [
#             "quay.io/tigera/operator@sha256:5e1d551b5a711592472f4a3cc4645698d5f826da4253f0d47cfa5d5b641a2e1a",
#             "..."
#         ],
#         ...
#     }
# ]
OPERATOR_IMAGE_DIGEST=$(docker image inspect ${OPERATOR_IMAGE} | jq -r '.[0].RepoDigests[] | select(. | contains("quay.io/tigera/operator"))')

# Set the operator container image by digest in the tigera-operator deployment spec embedded in the CSV.
yq write -i ${CSV} spec.install.spec.deployments[0].spec.template.spec.containers[0].image ${OPERATOR_IMAGE_DIGEST}

# Set the previous version of the operator that this version replaces.
if [[ "${PREV_VERSION}" != "0.0.0" ]]; then
    yq write -i ${CSV} spec.replaces tigera-operator.v${PREV_VERSION}
fi
