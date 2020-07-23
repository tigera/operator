#!/bin/bash
set -ex

CALICO_BASE_URL=https://docs.projectcalico.org
ENTERPRISE_BASE_URL=https://docs.tigera.io

# Get the Calico version installed by the operator.
CALICO_VERSION=$(yq read config/calico_versions.yml components.typha.version)

# Get the Calico Enterprise version installed by the operator.
ENTERPRISE_VERSION=$(yq read config/enterprise_versions.yml components.cnx-manager.version)

# If Calico version is something other than master, then strip the patch version
# numbers for both Calico and Enterprise and update the base urls.
if [ "${CALICO_VERSION}" == "master" ]; then
	CALICO_BASE_URL=${CALICO_BASE_URL}/master
	ENTERPRISE_BASE_URL=${ENTERPRISE_BASE_URL}/master
else
	CALICO_VERSION=$(sed -e 's/\.[0-9]\+$//' <<< $CALICO_VERSION)
	ENTERPRISE_VERSION=$(sed -e 's/\.[0-9]\+$//' <<< $ENTERPRISE_VERSION)

	CALICO_BASE_URL=${CALICO_BASE_URL}/archive/${CALICO_VERSION}
	ENTERPRISE_BASE_URL=${ENTERPRISE_BASE_URL}/${ENTERPRISE_VERSION}
fi

# Update the operator manifests.
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-tigera-operator.yaml --output deploy/operator.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-role-tigera-operator.yaml --output deploy/role.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-rolebinding-tigera-operator.yaml --output deploy/role_binding.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/02-serviceaccount-tigera-operator.yaml --output deploy/role_binding.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/tigera-operator/00-namespace-tigera-operator.yaml --output deploy/00-namespace.yaml

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

# Update the Calico CRDs.
for resource in $CALICO_RESOURCES; do
	curl ${CALICO_BASE_URL}/manifests/ocp/crds/calico/kdd/crd.projectcalico.org_${resource}.yaml --output deploy/crds/calico/crd.projectcalico.org_${resource}.yaml
done

# Update installation and tigerastatus CRDs.
curl ${CALICO_BASE_URL}/manifests/ocp/crds/01-crd-installation.yaml --output deploy/crds/operator.tigera.io_installations_crd.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/crds/01-crd-tigerastatus.yaml --output deploy/crds/operator.tigera.io_tigerastatuses_crd.yaml
curl ${CALICO_BASE_URL}/manifests/ocp/01-cr-installation.yaml --output deploy/crds/operator_v1_installation_cr.yaml

ENTERPRISE_RESOURCES="
apiserver
compliance
intrusiondetection
logcollector
logstorage
managementclusterconnection
manager
"

# Update the operator v1 enterprise CRDs.
for resource in $ENTERPRISE_RESOURCES; do
	curl ${ENTERPRISE_BASE_URL}/manifests/ocp/crds/01-crd-${resource}.yaml --output deploy/crds/operator.tigera.io_${resource}s_crd.yaml
done

ENTERPRISE_RESOURCES="
globalalerts
globalalerttemplates
globalreports
globalreporttypes
globalthreatfeeds
licensekeys
managedclusters
remoteclusterconfigurations
stagedglobalnetworkpolicies
stagedkubernetesnetworkpolicies
stagednetworkpolicies
tiers
"

if [ "${ENTERPRISE_VERSION}" == "v3.0" ]; then
	BASE_PATH="${ENTERPRISE_BASE_URL}/manifests/ocp/crds/calico/ee-kdd/02-crd-"
else
	BASE_PATH="${ENTERPRISE_BASE_URL}/manifests/ocp/crds/calico/kdd/crd.projectcalico.org_"
fi

# Update the Calico Enterprise CRDs.
for resource in $ENTERPRISE_RESOURCES; do
	curl ${BASE_PATH}${resource}.yaml --output deploy/crds/enterprise/02-crd-${resource}.yaml
done

ELASTIC_RESOURCES="
apmserver
elasticsearch
kibana
trustrelationship
"

# Update the Elastic CRDs.
for resource in $ELASTIC_RESOURCES; do
	curl ${ENTERPRISE_BASE_URL}/manifests/ocp/crds/01-crd-eck-${resource}.yaml -o deploy/crds/elastic/${resource}-crd.yaml
done

ENTERPRISE_RESOURCES="
apiserver
compliance
intrusiondetection
logcollector
logstorage
manager
"

# Update the Enterprise CRs.
for resource in $ENTERPRISE_RESOURCES; do
	curl ${ENTERPRISE_BASE_URL}/manifests/ocp/01-cr-${resource}.yaml --output deploy/crds/operator_v1_${resource}_cr.yaml
done

