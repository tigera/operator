#!/bin/bash
# Copyright (c) 2020 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
