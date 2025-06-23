// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main is a simple utility to increment a patch version
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/blang/semver/v4"
)

func main() {
	// Increment the patch version of the current module.
	// This is used to ensure that the module version is always incremented
	// when a new patch is released.

	if len(os.Args) < 2 {
		fmt.Println("Usage: increment_patch <version>")
		fmt.Println("Example: increment_patch v1.39.0")
		return
	}

	inputVersion := os.Args[1]

	// Remove the 'v' prefix if it exists
	// and parse the version string.
	strippedVersion := strings.Trim(inputVersion, "v")

	currentVersion, err := semver.Make(strippedVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing version `%s`: %s\n", inputVersion, err)
		return
	}

	// There are two possible formats for input version that we're likely to run into:
	// 1. v1.39.0-0.dev-116-g61909055
	// 		This means that we've created a 'v1.39.0-0.dev' tag to indicate what the next
	// 		version will be; this is for when we haven't created a release for this branch yet.
	// 		In this case, we want to use the version that's already in the tag, minus the -0.dev
	// 2. v1.36.9-44-g61909055
	// 		This means we've released v1.36.9 and we're 44 commits after that release, meaning
	// 		that the next version will be v1.36.10. In this case we want to increment the
	// 		patch version. This is also the case if we're already on a tag and got `v1.36.9` as input.
	if !strings.Contains(strippedVersion, ".dev-") {
		err = currentVersion.IncrementPatch()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error incrementing version `%s`: %s\n", inputVersion, err)
			return
		}
	}

	fmt.Printf("v%s\n", currentVersion.FinalizeVersion())
}
