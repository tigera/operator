#!/bin/bash
#
# usage: update_hashrelease_fork.sh <url>
#
# ensure <url> exists

set -exo pipefail

URL=$1

# personalRemote is the fork where branches will be pushed to and pull requests submitted from.
# can be the same as 'origin' but recommended to be a personal fork or bot-owned fork.
personalRemote=${REMOTE:-git@github.com:tigera/operator-cloud.git}

versions=$(curl $URL/pinned_versions.yml | yq r - "[0]")
releaseName=$(yq r - "release_name" <<< $versions)
releaseNickname=$(cut -d- -f6 <<< $releaseName)
operatorImageVersion=$(yq r - "tigera-operator.version" <<< $versions)
branch=release-$(cut -d '.' -f 1,2 <<< $operatorImageVersion)
commit=$(cut -d- -f3 <<< $operatorImageVersion | cut -c 2-)

dir=$(mktemp -d)

function precheck(){
    if [[ "${releaseName}" == *"master"* ]]; then
        echo "$releaseName is a master hashrelease, not updating the fork"
        exit 1;
    else
        echo "Updating fork for $releaseName"
    fi
}

function clone() {
    # git clone git@github.com:tigera/operator-cloud.git $dir
    git init -b null $dir
    pushd $dir
    git remote add origin git@github.com:tigera/operator-cloud.git
    git fetch origin

    git remote add upstream git@github.com:tigera/operator.git
    git fetch upstream

    git remote add personal $personalRemote
    git fetch personal

    gh repo set-default tigera/operator-cloud

    popd
}

function merge() {
    pushd $dir
    git checkout -b update-$branch origin/$branch
    git merge $commit
    popd
}

function pullrequest() {
    pushd $dir
    git push personal update-$branch
    gh pr create --base $branch --title "merge upstream $branch" --body "Merging upstream operator updates to $branch up to $commit in sync with [enterprise hashrelease '$releaseNickname']($URL)"
}

precheck
clone
merge
pullrequest
