#!/bin/bash
#
# This script updates a bundle generated by `operator-sdk generate bundle` so
# that we can certify it.
#
# This script should be not be run directly. See the bundle target in the
# Makefile.
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

OPERATOR_IMAGE=quay.io/tigera/operator:v${VERSION}
OPERATOR_IMAGE_INSPECT=$(echo $OPERATOR_IMAGE_INSPECT | base64 -d)
OPERATOR_IMAGE_DIGEST=$(echo $OPERATOR_IMAGE_INSPECT | jq -r '.[0].RepoDigests[] | select(. | contains("quay.io/tigera/operator"))')

CSV=bundle/${VERSION}/manifests/operator.clusterserviceversion.yaml

# Rearrange the bundle layout.
mkdir bundle/${VERSION}
mv bundle/{metadata,manifests} bundle/${VERSION}

#
# Update the CSV. Set the operator image container image and creation timestamp annotations.
#
yq write -i ${CSV} metadata.annotations.containerImage ${OPERATOR_IMAGE_DIGEST}
TIMESTAMP=$(echo ${OPERATOR_IMAGE_INSPECT} | jq -r .[0].Created)
yq write -i ${CSV} metadata.annotations.createdAt ${TIMESTAMP}

# Add the features annotations
FEATURES=metadata.annotations.features.operators.openshift.io
yq write -i ${CSV} ${FEATURES}/disconnected "false"
yq write -i ${CSV} ${FEATURES}/fips-compliant "false"
yq write -i ${CSV} ${FEATURES}/proxy-aware "false"
yq write -i ${CSV} ${FEATURES}/tls-profiles "false"
yq write -i ${CSV} ${FEATURES}/token-auth-aws "false"
yq write -i ${CSV} ${FEATURES}/token-auth-azure "false"
yq write -i ${CSV} ${FEATURES}/token-auth-gcp "false"
yq write -i ${CSV} ${FEATURES}/cnf "false"
yq write -i ${CSV} ${FEATURES}/cni "true"
yq write -i ${CSV} ${FEATURES}/csi "false"

# Set the operator container image by digest in the tigera-operator deployment spec embedded in the CSV.
yq write -i ${CSV} spec.install.spec.deployments[0].spec.template.spec.containers[0].image ${OPERATOR_IMAGE_DIGEST}

# Set the CSV name.
yq write -i ${CSV} metadata.name tigera-operator.v${VERSION}

# Set the previous version of the operator that this version replaces.
if [[ "${PREV_VERSION}" != "0.0.0" ]]; then
    yq write -i ${CSV} spec.replaces tigera-operator.v${PREV_VERSION}
fi

# Set the CSV to ignore previous versions when updating. Use brackets to preserve the
# dot in the key "olm.skipRange".
yq write -i ${CSV} --style double 'metadata.annotations[olm.skipRange]' \<${VERSION}

# Add required 'relatedImages' to CSV
# E.g.
#
#   relatedImages:
#     - name: tigera-operator
#       image: quay.io/tigera/operator@sha256:b4e3eeccfd3d5a931c07f31c244b272e058ccabd2d8155ccc3ff52ed78855e69
yq write -i ${CSV} spec.relatedImages[0].name tigera-operator
yq write -i ${CSV} spec.relatedImages[0].image ${OPERATOR_IMAGE_DIGEST}

#
# Now start updates to the bundle dockerfile. First update the package name.
#
sed -i 's/\(operators\.operatorframework\.\io\.bundle\.package\.v1\)=operator/\1=tigera-operator/' bundle.Dockerfile

# Supported OpenShift versions. Specify min version.
openshiftVersions=v4.6

# Add in required labels
cat <<EOF >> bundle.Dockerfile
LABEL com.redhat.openshift.versions="${openshiftVersions}"
LABEL com.redhat.delivery.backport=true
LABEL com.redhat.delivery.operator.bundle=true
EOF

# Remove unneeded labels
sed -i 's/.*operators\.operatorframework\.io\.metrics.*//' bundle.Dockerfile
sed -i 's/.*operators\.operatorframework\.io\.test\.config\.v1.*//' bundle.Dockerfile
sed -i 's/.*operators\.operatorframework\.io\.test\.mediatype\.v1.*//' bundle.Dockerfile

# Fix the bundle path
sed -i 's/COPY bundle\/manifests.*//' bundle.Dockerfile
sed -i 's/COPY bundle\/metadata.*//' bundle.Dockerfile
cat <<EOF >> bundle.Dockerfile
COPY ${VERSION}/manifests /manifests/
COPY ${VERSION}/metadata /metadata/
EOF

# Delete empty permissions (we only set clusterPermissions) otherwise the CSV
# validation fails
yq delete -i ${CSV} spec.install.spec.permissions

# Rename CSV to "tigera-operator".
mv bundle/${VERSION}/manifests/operator.clusterserviceversion.yaml bundle/${VERSION}/manifests/tigera-operator.clusterserviceversion.yaml

# Remove unneeded empty lines
sed -i '/^$/d' bundle.Dockerfile

# Lastly move the dockerfile to the bundle dir, renaming it with the version
mv bundle.Dockerfile bundle/bundle-v${VERSION}.Dockerfile

#
# Update annotations file. Update package name.
#
sed -i 's/\(operators\.operatorframework\.io\.bundle\.package\.v1\): operator/\1: tigera-operator/' bundle/${VERSION}/metadata/annotations.yaml

# Remove unneeded labels
sed -i 's/.*operators\.operatorframework\.io\.metrics.*//' bundle/${VERSION}/metadata/annotations.yaml
sed -i 's/.*operators\.operatorframework\.io\.test.*//' bundle/${VERSION}/metadata/annotations.yaml

# Remove unneeded empty lines
sed -i '/^$/d' bundle/${VERSION}/metadata/annotations.yaml

# Add required com.redhat.openshift.versions
cat <<EOF >> bundle/${VERSION}/metadata/annotations.yaml
  com.redhat.openshift.versions: ${openshiftVersions}
EOF
