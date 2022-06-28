#!/bin/bash
set -e

if ! tag=$(git describe --exact-match --tags HEAD); then
	echo "Not on a tag - no need to release";
	exit 0
fi

if [[ ! "${tag}" =~ ^cloud-v[0-9]+\.[0-9]+\.[0-9]+-[-0-9]+$ ]]; then
	echo "tag ${tag} does not match the format cloud-vX.Y.Z-<release>"
	exit 1
fi

if [[ ! "$(git rev-parse --abbrev-ref HEAD)" =~ (release-v*.*|master|cloud-dev|cloud-v*.*|staging) ]]; then
	echo "not on 'master', 'cloud-dev', 'cloud-v*.*', 'staging', or 'release-vX.Y'"
	exit 0
fi

# Skip releasing if the image already exists. No guarantee that a tagged build will only be run once. We want the build to
# pass in the case where the image exists.
if ! make release-check-image-exists VERSION=${tag}; then
	echo "Image tag already exists, no need to release"
	exit 0
fi

echo "On a git tag - building release: ${tag}"
make release VERSION=${tag}
make release VERSION=${tag} BUILD_IMAGE=tigera-tesla/operator-cloud

echo "Publish release ${tag}"
make release-publish-images VERSION=${tag}
make release-publish-images VERSION=${tag} BUILD_IMAGE=tigera-tesla/operator-cloud
