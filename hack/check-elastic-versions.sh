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

# Verify that all ES/Kibana version references within operator are consistent.
# Checks enterprise_versions.yml against the generated Go code in
# pkg/components/enterprise.go, and ensures ES and Kibana use the same version.

set -euo pipefail

VERSIONS_FILE="config/enterprise_versions.yml"
COMPONENTS_FILE="pkg/components/enterprise.go"

# Extract versions from enterprise_versions.yml.
local_es=$(grep -A1 'eck-elasticsearch:' "$VERSIONS_FILE" | grep -oP 'version:\s*\K\S+')
local_kbn=$(grep -A1 'eck-kibana:' "$VERSIONS_FILE" | grep -oP 'version:\s*\K\S+')

echo "eck-elasticsearch version (YAML): $local_es"
echo "eck-kibana version (YAML): $local_kbn"

# Extract versions from generated Go code.
go_es=$(grep -A1 'ComponentEckElasticsearch' "$COMPONENTS_FILE" | grep -oP 'Version:\s*"\K[^"]+')
go_kbn=$(grep -A1 'ComponentEckKibana' "$COMPONENTS_FILE" | grep -oP 'Version:\s*"\K[^"]+')

echo "eck-elasticsearch version (Go): $go_es"
echo "eck-kibana version (Go): $go_kbn"

errors=0

# YAML and Go must match.
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

# ES and Kibana must use the same version.
if [[ "$local_es" != "$local_kbn" ]]; then
    echo "ERROR: eck-elasticsearch ($local_es) and eck-kibana ($local_kbn) versions differ"
    errors=1
fi

if [[ "$errors" -ne 0 ]]; then
    echo
    echo "ES/Kibana version check FAILED."
    echo "Update ${VERSIONS_FILE} and run 'make gen-versions' to sync."
    exit 1
fi

echo "All ES/Kibana versions are consistent."
