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
	echo "No CSVs found in ${CSV_DIR}"
	exit 1
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

# Determine the latest CSV version. We can't use git tags because not all tagged
# releases may be published on the RH catalog
# - Find all directories in the CSV dir, printing only the basename (and not the full path)
# - Reverse sort using version sort. Our version format is simple enough that built-in sort should handle it.
# - Get the top item
LATEST=$(find ${BUNDLE_DIR}/* -type d -printf "%f\n" | sort --reverse --version-sort | head -n 1)

# Create a new package manifest file in the bundle directory, specifying the latest CSV.
# We assume that we have a single channel named 'stable'.
cat > ${BUNDLE_DIR}/tigera-operator.package.yaml <<EOF
channels:
- currentCSV: tigera-operator.v$LATEST
  name: stable
defaultChannel: stable
packageName: tigera-operator
EOF

# Finally, zip up the bundle.
cwd=$(pwd)
pushd .
cd ${CSV_DIR} && zip -FS -r ${cwd}/build/_output/bundle/bundle.zip .
popd
