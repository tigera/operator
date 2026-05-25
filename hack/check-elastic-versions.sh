#!/bin/bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify that operator's ES/Kibana versions are not behind calico-private.
# Catches forgotten operator updates after an ES/Kibana bump in calico-private.

set -euo pipefail

CALICO_PRIVATE_REPO="tigera/calico-private"
VERSIONS_FILE="config/enterprise_versions.yml"

# Determine which calico-private branch to compare against.
# The title field in enterprise_versions.yml holds the Calico Enterprise
# version (e.g. "v3.21.7" on release branches, "master" on master).
# Extract the major.minor to derive the calico-private release branch.
ee_title=$(grep '^title:' "$VERSIONS_FILE" | awk '{print $2}')
if [[ "$ee_title" == "master" ]]; then
    calico_branch="master"
elif [[ "$ee_title" =~ ^v([0-9]+\.[0-9]+) ]]; then
    calico_branch="release-v${BASH_REMATCH[1]}"
else
    echo "WARNING: could not determine calico-private branch from title '$ee_title', defaulting to master"
    calico_branch="master"
fi

echo "Comparing operator versions against ${CALICO_PRIVATE_REPO}@${calico_branch}"

# Fetch calico-private's ES Makefile version as the upstream source of truth.
upstream_es=$(gh api "repos/${CALICO_PRIVATE_REPO}/contents/third_party/elasticsearch/Makefile?ref=${calico_branch}" \
    --jq '.content' | base64 -d | grep -oP '^ELASTIC_VERSION=\K\S+' | head -1)

if [[ -z "$upstream_es" ]]; then
    echo "WARNING: could not fetch ELASTIC_VERSION from ${CALICO_PRIVATE_REPO}@${calico_branch}, skipping check"
    exit 0
fi

echo "calico-private ES/Kibana version: $upstream_es"

# Extract local operator versions from enterprise_versions.yml.
local_es=$(grep -A1 'eck-elasticsearch:' "$VERSIONS_FILE" | grep -oP 'version:\s*\K\S+')
local_kbn=$(grep -A1 'eck-kibana:' "$VERSIONS_FILE" | grep -oP 'version:\s*\K\S+')

echo "operator eck-elasticsearch version (YAML): $local_es"
echo "operator eck-kibana version (YAML): $local_kbn"

# Extract versions from generated Go code.
COMPONENTS_FILE="pkg/components/enterprise.go"
go_es=$(grep -A1 'ComponentEckElasticsearch' "$COMPONENTS_FILE" | grep -oP 'Version:\s*"\K[^"]+')
go_kbn=$(grep -A1 'ComponentEckKibana' "$COMPONENTS_FILE" | grep -oP 'Version:\s*"\K[^"]+')

echo "operator eck-elasticsearch version (Go): $go_es"
echo "operator eck-kibana version (Go): $go_kbn"

errors=0

# Internal consistency: YAML and Go must match.
if [[ "$local_es" != "$go_es" ]]; then
    echo "ERROR: enterprise_versions.yml eck-elasticsearch ($local_es) does not match enterprise.go ($go_es)"
    echo "       Run 'make gen-versions' to regenerate."
    errors=1
fi

if [[ "$local_kbn" != "$go_kbn" ]]; then
    echo "ERROR: enterprise_versions.yml eck-kibana ($local_kbn) does not match enterprise.go ($go_kbn)"
    echo "       Run 'make gen-versions' to regenerate."
    errors=1
fi

if [[ "$local_es" != "$local_kbn" ]]; then
    echo "ERROR: eck-elasticsearch ($local_es) and eck-kibana ($local_kbn) versions differ in ${VERSIONS_FILE}"
    errors=1
fi

# Cross-repo: operator must match calico-private.
if [[ "$local_es" != "$upstream_es" ]]; then
    echo "ERROR: operator eck-elasticsearch version ($local_es) does not match calico-private ($upstream_es)"
    errors=1
fi

if [[ "$local_kbn" != "$upstream_es" ]]; then
    echo "ERROR: operator eck-kibana version ($local_kbn) does not match calico-private ($upstream_es)"
    errors=1
fi

if [[ "$errors" -ne 0 ]]; then
    echo
    echo "Operator ES/Kibana versions are out of sync."
    echo "Update ${VERSIONS_FILE} and run 'make gen-versions' to sync."
    exit 1
fi

echo "Operator ES/Kibana versions are consistent and match calico-private."

