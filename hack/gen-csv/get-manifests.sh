#!/bin/bash
#
# This script downloads Calico and operator manifests that are used to generate
# ClusterServiceVersions.
set -ex

# Get the base path for the Calico docs site. This will be used to download manifests.
CALICO_BASE_URL=https://docs.projectcalico.org

if [ -f config/calico_versions.yml ]; then
    CALICO_VERSION=$(yq read config/calico_versions.yml components.typha.version)
else
    echo "Could not find Calico versions file."
    exit 1
fi

# If Calico version is something other than master, then strip the patch version
# numbers for both Calico and Enterprise and update the base urls.
if [ "${CALICO_VERSION}" == "master" ]; then
    CALICO_BASE_URL=${CALICO_BASE_URL}/master
else
    CALICO_VERSION=$(sed -e 's/\.[0-9]\+$//' <<< $CALICO_VERSION)
    CALICO_BASE_URL=${CALICO_BASE_URL}/archive/${CALICO_VERSION}
fi

# Download operator manifests.
function downloadOperatorManifests() {
    curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-tigera-operator.yaml --output ${DEPLOY_DIR}/operator.yaml
    curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-role-tigera-operator.yaml --output ${DEPLOY_DIR}/role.yaml

    # Download the installation CR so that the alm-examples annotation is generated.
    curl ${CALICO_BASE_URL}/manifests/ocp/01-cr-installation.yaml --output ${DEPLOY_DIR}/01-cr-installation.yaml
}

# Download the installation and tigerastatus CRDs.
function downloadOperatorCRDs() {
    curl ${CALICO_BASE_URL}/manifests/ocp/crds/01-crd-installation.yaml --output ${CSV_DIR}/operator.tigera.io_installations_crd.yaml
    curl ${CALICO_BASE_URL}/manifests/ocp/crds/01-crd-tigerastatus.yaml --output ${CSV_DIR}/operator.tigera.io_tigerastatuses_crd.yaml
}

function downloadCalicoCRDs() {
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
}

downloadOperatorManifests
downloadOperatorCRDs
downloadCalicoCRDs
