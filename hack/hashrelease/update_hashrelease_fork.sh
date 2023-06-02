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
releaseName=`curl $URL/pinned_versions.yml | yq r - "[0].release_name"`
releaseAlias=`echo $releaseName | cut -d- -f6`
operatorVersionString=`curl $URL/pinned_versions.yml | yq r - "[0].tigera-operator.version"`

dir=$(mktemp -d)

function precheck(){
    if [[ "${releaseName}" == *"master"* ]]; then
        echo "$releaseName is a master hashrelease, not updating the fork"
        exit 1;
    else
        echo "Updating fork for $releaseName"
    fi
}

function getOperatorReleaseVersion(){
    # eg. v1.30
    echo $operatorVersionString | cut -d '.' -f 1,2
}

function getOperatorCommit(){
    # eg. 108e449986a2
    echo $operatorVersionString | cut -d- -f3 | cut -c 2-
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
    operatorCommit=$(getOperatorCommit)
    git checkout -b update-to-$releaseAlias-hashrelease $operatorCommit
    git merge $operatorCommit
    popd
}

function pullrequest() {
    pushd $dir
    operatorBranch=release-$(getOperatorReleaseVersion)
    git push personal update-to-$releaseAlias-hashrelease 
    gh pr create --base $operatorBranch --title "merge upstream updates from $releaseAlias hashrelease" --body "Merging upstream operator updates based on [$releaseAlias enterprise hashrelease]($URL)"
}

precheck
clone
merge
pullrequest
