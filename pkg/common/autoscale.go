// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package common

// GetTyphaScaleCount will return the number of Typhas needed for the number of nodes.
func GetExpectedTyphaScale(nodes int) int {
	var maxNodesPerTypha int = 200
	// This gives a count of how many 200s so we need 1+ this number to get at least
	// 1 typha for every 200 nodes.
	typhas := (nodes / maxNodesPerTypha) + 1
	// We add one more to ensure there is always 1 extra for high availability purposes.
	typhas += 1
	if nodes <= 3 {
		// If we don't have enough nodes to have 3 typhas then make sure there is one typha for each node.
		typhas = nodes
	} else if typhas < 3 { // If typhas is less than 3 always make sure we have 3
		typhas = 3
	}
	return typhas
}
