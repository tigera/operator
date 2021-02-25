#!/bin/bash
#
# This script generates a CSV bundle zip file that can be uploaded at
# connect.redhat.com to publish new operator versions.
#
# Pre-generated CSVs using `make gen-csv` are copied to the bundle directory and the package manifest
# file is updated with the latest CSV version.

set -e
set -x

CSV_DIR=build/_output/bundle/olm-catalog/tigera-operator

BUNDLE_DIR=deploy/olm-catalog/tigera-operator

if [ ! -d "${CSV_DIR}" ]; then
    mkdir -p ${CSV_DIR}
fi

# Create the bundle directory if it doesn't already exist.
if [ ! -d "${BUNDLE_DIR}" ]; then
    mkdir -p ${BUNDLE_DIR}
fi

# Copy over all generated CSVs to the deploy directory.
for csv in `find ${CSV_DIR}/* -type d`
do
    echo $csv
    cp -R ${csv} ${BUNDLE_DIR}
done

# Get array of all of the CSV versions in descending order. Note: We can't use git tags because not all tagged
# releases may be published on the RH catalog
# - Find all directories in the CSV dir, printing only the basename (instead of full path)
# - Reverse sort using version sort. Our version format is simple enough that built-in sort should handle it.
versions=()
for v in `find ${BUNDLE_DIR}/* -type d -printf "%f\n" | sort --reverse --version-sort`; do
    versions+=($v)
done

# Update every CSV so that we have a chain of CSVs each replacing the next.
# E.g., if we have the CSV versions v1.3.1, v1.3.2, and v1.6.2 then
# - update the v1.6.2 CSV by setting its `spec.replaces` to v1.3.2
# - update the v1.3.2 CSV by setting its `spec.replaces` to v1.3.1
# - nothing is done for v1.3.1 since it doesn't replace any version
#
# If we only have 1 CSV, we skip this updating.
NUM_VERSIONS=${#versions[@]}

LATEST_VERSION=${versions[0]}

if [[ $NUM_VERSIONS -gt 1 ]]; then
    # bash arrays are 0-indexed. Get the 2nd last index.
    # If we have the following versions in the array: v1.6.2, v1.3.2, v1.3.1,
    # then the last one to update is the 1th indexed version.
    END_INDEX=$(($NUM_VERSIONS - 2))

    # Loop through all versions up to the end index
    for i in $(seq 0 $END_INDEX); do
        # Versions are in reverse order so the version in the next index is the
        # previous version to the current version.
        next_index=$(($i + 1))
        prev_version=${versions[$next_index]}

        this_version=${versions[$i]}
        this_csv=${BUNDLE_DIR}/${this_version}/tigera-operator.v${this_version}.clusterserviceversion.yaml

        echo "Setting 'spec.replaces' in ${versions[$i]} to $prev_version"
        yq write -i ${this_csv} spec.replaces tigera-operator.v${prev_version}
    done
fi

# Create a new package manifest file in the bundle directory, specifying the latest CSV.
# We assume that we have a single channel named 'stable'.
cat > ${BUNDLE_DIR}/tigera-operator.package.yaml <<EOF
channels:
- currentCSV: tigera-operator.v${LATEST_VERSION}
  name: stable
defaultChannel: stable
packageName: tigera-operator
EOF
