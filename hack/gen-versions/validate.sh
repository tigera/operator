#!/bin/bash
set -e

git fetch origin

function modded() {
    file=$1
    git diff --name-only HEAD..$(git merge-base HEAD origin/master) $file
}

function xor_modded() {
    file1Modded=$(modded $1)
    file2Modded=$(modded $2)

    # return error code if only one file is modified
    test -n "$file1Modded" -a -n "$file2Modded" || \
    test -z "$file1Modded" -a -z "$file2Modded"
}

xor_modded config/calico_versions.yml pkg/components/calico.go || echo \
"invalid: must modify both config/calico_versions.yml and pkg/components/calico.go"

xor_modded config/enterprise_versions.yml pkg/components/enterprise.go || echo \
"invalid: must modify both config/enterprise_versions.yml pkg/components/enterprise.go"

echo valid
