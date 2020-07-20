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

# VERSION is the version of the operator to publish.
if [[ -z "${VERSION}" ]]; then
	echo VERSION is undefined - run with vars VERSION=X.Y.Z PREV_VERSION=D.E.F
	exit 1
fi

# OPERATOR_IMAGE_INSPECT is the base64-encoded output from "docker image inspect quay.io/tigera/operator:v${VERSION}"
if [[ -z "${OPERATOR_IMAGE_INSPECT}" ]]; then
	echo OPERATOR_IMAGE_INSPECT is undefined
	exit 1
fi

# PREV_VERSION is the version of the operator that VERSION replaces. If this version does not replace a version, use 0.0.0
if [[ -z "${PREV_VERSION}" ]]; then
	echo PREV_VERSION is undefined - run with vars VERSION=X.Y.Z PREV_VERSION=D.E.F
	exit 1
fi

OPERATOR_IMAGE_INSPECT=$(echo $OPERATOR_IMAGE_INSPECT | base64 -d)

OPERATOR_IMAGE_DIGEST=$(echo $OPERATOR_IMAGE_INSPECT | jq -r '.[0].RepoDigests[] | select(. | contains("quay.io/tigera/operator"))')

# This is the top-level directory of this script's artifacts.
OUTPUT_DIR=build/_output/bundle

# This directory serves two purposes.
# - it's the source directory of CRDs that we want in the resulting CSV package.
# - it's the output directory of the CSV output from the 'operator-sdk generate csv' command.
CSV_DIR=${OUTPUT_DIR}/olm-catalog/tigera-operator/${VERSION}
mkdir -p ${CSV_DIR}

DEPLOY_DIR=${OUTPUT_DIR}/deploy
mkdir -p ${DEPLOY_DIR}

# Get the base path for the Calico docs site. This will be used to download manifests.
CALICO_BASE_URL=https://docs.projectcalico.org
CALICO_VERSION=$(yq read config/calico_versions.yml components.typha.version)

# If Calico version is something other than master, then strip the patch version
# numbers for both Calico and Enterprise and update the base urls.
if [ "${CALICO_VERSION}" == "master" ]; then
	CALICO_BASE_URL=${CALICO_BASE_URL}/master
else
	CALICO_VERSION=$(sed -e 's/\.[0-9]\+$//' <<< $CALICO_VERSION)
	CALICO_BASE_URL=${CALICO_BASE_URL}/archive/${CALICO_VERSION}
fi

# Download operator manifests.
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-tigera-operator.yaml --output ${DEPLOY_DIR}/operator.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-role-tigera-operator.yaml --output ${DEPLOY_DIR}/role.yaml

# Download the installation and tigerastatus CRDs.
curl ${CALICO_BASE_URL}/manifests/ocp/crds/01-crd-installation.yaml --output ${CSV_DIR}/operator.tigera.io_installations_crd.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/crds/01-crd-tigerastatus.yaml --output ${CSV_DIR}/operator.tigera.io_tigerastatuses_crd.yaml

CALICO_RESOURCES="
bgpconfigurations
bgppeers
blockaffinities
clusterinformations
felixconfigurations
globalnetworkpolicies
globalnetworksets
hostendpoints
ipamblocks
ipamconfigs
ipamhandles
ippools
kubecontrollersconfigurations
networkpolicies
networksets
"

# Download the Calico CRDs into CSV dir.
for resource in $CALICO_RESOURCES; do
	curl ${CALICO_BASE_URL}/manifests/ocp/crds/calico/kdd/crd.projectcalico.org_${resource}.yaml --output ${CSV_DIR}/crd.projectcalico.org_${resource}.yaml
done

CSV=${CSV_DIR}/tigera-operator.v${VERSION}.clusterserviceversion.yaml

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
  --deploy-dir ${DEPLOY_DIR} \
  --apis-dir pkg/apis/operator/v1/ \
  --make-manifests=false \
  --verbose \
  --interactive=false \
  --output-dir=${OUTPUT_DIR}

OPERATOR_IMAGE=quay.io/tigera/operator:v${VERSION}

# Set the operator image container image and creation timestamp annotations.
yq write -i ${CSV} metadata.annotations.containerImage ${OPERATOR_IMAGE}
TIMESTAMP=$(echo ${OPERATOR_IMAGE_INSPECT} | jq -r .[0].Created)
yq write -i ${CSV} metadata.annotations.createdAt ${TIMESTAMP}

# Set the operator container image by digest in the tigera-operator deployment spec embedded in the CSV.
yq write -i ${CSV} spec.install.spec.deployments[0].spec.template.spec.containers[0].image ${OPERATOR_IMAGE_DIGEST}

# Set the previous version of the operator that this version replaces.
if [[ "${PREV_VERSION}" != "0.0.0" ]]; then
    yq write -i ${CSV} spec.replaces tigera-operator.v${PREV_VERSION}
fi
