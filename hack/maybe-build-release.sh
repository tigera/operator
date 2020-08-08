#!/bin/bash
set -e

if ! tag=$(git describe --exact-match --tags HEAD); then
	echo "Not on a tag - no need to release";
	exit 0
fi

echo "On a git tag - building release: ${tag}"
make release VERSION=${tag}

echo "Publish release ${tag}"
make release-publish-images VERSION=${tag}

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

docker login -u unused scan.connect.redhat.com --password-stdin <<< ${OPERATOR_INIT_RH_REGISTRY_KEY}
redhatImage=scan.connect.redhat.com/$OPERATOR_INIT_RH_PROJECTID/operator-init:${tag}

if ! docker pull $redhatImage 2>/dev/null; then
	echo "tagging and pushing operator-init image..."
	quayImage=quay.io/tigera/operator-init:${tag}
	docker pull $quayImage
	docker tag $quayImage $redhatImage
	docker push $redhatImage
else
	echo "operator-init image exists on scan.connect.redhat.com, skipping tagging/pushing"
fi
