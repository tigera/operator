// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package utils

import (
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CreatePatch takes an 'original' and an updated resource and generates a patch
// to go from the original to the updated.
func CreatePatch(og, new interface{}) (client.Patch, error) {
	ogjson, err := json.Marshal(og)
	if err != nil {
		return nil, err
	}
	newjson, err := json.Marshal(new)
	if err != nil {
		return nil, err
	}

	patch, err := strategicpatch.CreateTwoWayMergePatch(ogjson, newjson, og)
	if err != nil {
		return nil, err
	}

	return client.RawPatch(types.MergePatchType, patch), nil
}
