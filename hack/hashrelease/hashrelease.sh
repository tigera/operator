#!/bin/bash
#/ Usage: hashrelease.sh [url]
#/ Prerequisite: you must have already have merged changes and be on the corresponding commit of the upstream hashrelease

set -eo pipefail

# Initialize variables to create a cloud hash release based on enterprise.
tmpDir=$(mktemp -d)
# trim trailing slash
hashReleaseUrl=${1%/}
eeVersionsUrl=${hashReleaseUrl}/pinned_versions.yml

# Download the enterprise pinned version file from upstream hash releases.
curl $eeVersionsUrl | yq read - '[0]' > $tmpDir/hashrelease_versions.yml
make gen-versions-enterprise EE_VERSIONS=$tmpDir/hashrelease_versions.yml

cp $(dirname $0)/_images.go pkg/components/images.go
cp $(dirname $0)/_cloud_images.go pkg/components/cloud_images.go

releaseName=$(yq read $tmpDir/hashrelease_versions.yml release_name)-tesla

make image tag-images IMAGETAG=$releaseName
# TODO: figure out how to push image without amd64 suffix because this only pushes the amd64 one
echo make push IMAGETAG=$releaseName
