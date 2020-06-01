#!/bin/bash

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
