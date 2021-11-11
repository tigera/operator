#!/bin/bash
set -e

tag=$1

# This image should exist locally since this script will be invoked by
# hack/maybe-build-release.sh
# RepoDigests should be a single result in brackets that we strip.
image=$(docker inspect --format='{{.RepoDigests}}' quay.io/tigera/operator:${tag} | sed 's|^\[\(.*\)\]$|\1|')

if [ "${image}" == "" ]; then
	echo "No digest found for image"
	exit 1
fi

# Submit the certification request. Note that "tag" used is a temporary tag that
# will be used for the certification scan. When we manually publish the passing
# image, we add the real tag and remove the temporary tag.
echo "Digest for tag ${tag} is ${image}. Triggering certification scan request..."
output=$(curl -s -H "Content-Type: application/json" \
	-H "X-API-KEY: ${RH_API_TOKEN}" \
	https://catalog.redhat.com/api/containers/v1/projects/certification/id/${OPERATOR_RH_PROJECTID}/requests/scans \
	-d "$(cat <<EOF
{
  "pull_spec": "${image}",
  "tag": "test-${image}"
}
EOF
)")

# Redact the project ID from the output.
echo "${output}" | sed -e 's|"href": "/v1/projects/certification/id/[a-zA-Z0-9]*"|XXX|' -e 's|\("cert_project"\): "\([a-zA-Z0-9]*\)",|\1: "XXX"|'
