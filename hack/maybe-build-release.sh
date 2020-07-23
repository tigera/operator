#!/bin/bash
set -ex

tag=$(git describe --exact-match --tags HEAD)
if [[ -z "${tag}" ]]; then
	echo "Not on a tag - no need to release";
	exit 0
fi

if [[ ! "$(git branch --show-current)" =~ (release-v*.*|master) ]]; then
	echo "not on 'master' or 'release-vX.Y'"
	exit 0
fi

echo "On a git tag - building release: ${tag}"
make release VERSION=${tag}

echo "Publish release ${tag}"
make release-publish-images VERSION=${tag}

echo "Tagging and pushing operator images to RedHat Connect for certification..."

docker login -u unused scan.connect.redhat.com --password-stdin <<< ${OPERATOR_RH_REGISTRY_KEY}
quayImage=quay.io/tigera/operator:$VERSION
redhatImage=scan.connect.redhat.com/$OPERATOR_RH_PROJECTID/operator:$VERSION
docker pull $quayImage
docker tag $quayImage $redhatImage
# Pushes to scan.connect.redhat.com fail if the image exists already. Return
# a success exit code so we can retry image pushes if needed.
docker push $redhatImage || true

docker login -u unused scan.connect.redhat.com --password-stdin <<< ${OPERATOR_INIT_RH_REGISTRY_KEY}
quayImage=quay.io/tigera/operator-init:$VERSION
redhatImage=scan.connect.redhat.com/$OPERATOR_INIT_RH_PROJECTID/operator:$VERSION
docker pull $quayImage
docker tag $quayImage $redhatImage
docker push $redhatImage || true
