#!/bin/bash
set -e

if ! tag=$(git describe --exact-match --tags HEAD); then
	echo "Not on a tag - no need to release";
	exit 0
fi

if [[ ! "${tag}" =~ ^cloud-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]; then
	echo "tag ${tag} does not match the format cloud-vX.Y.Z-<release>"
	exit 1
fi

if [[ ! "$(git rev-parse --abbrev-ref HEAD)" =~ (release-v*.*|master|cloud-dev) ]]; then
	echo "not on 'master', 'cloud-dev', or 'release-vX.Y'"
	exit 0
fi

echo "On a git tag - building release: ${tag}"
make release VERSION=${tag}

echo "Publish release ${tag}"
make release-publish-images VERSION=${tag}

if [[ "$(git rev-parse --abbrev-ref HEAD)" =~ (cloud-dev) ]]; then
	echo "on 'cloud-dev' branch, do not push to RedHat for certification"
	exit 0
fi

echo "Tagging and pushing operator images to RedHat Connect for certification..."

docker login -u unused scan.connect.redhat.com --password-stdin <<< ${OPERATOR_RH_REGISTRY_KEY}
redhatImage=scan.connect.redhat.com/$OPERATOR_RH_PROJECTID/operator:${tag}

# Pushes to scan.connect.redhat.com fail if the image exists already.
# If it already exists, skip tagging and pushing.
if ! docker pull $redhatImage 2>/dev/null; then
	echo "Tagging and pushing operator image..."
	quayImage=quay.io/tigera/operator:${tag}
	docker pull $quayImage
	docker tag $quayImage $redhatImage
	docker push $redhatImage
else
	echo "operator image exists on scan.connect.redhat.com, skipping tagging/pushing"
fi
