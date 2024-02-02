// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package ptr

import (
	"k8s.io/apimachinery/pkg/util/intstr"
)

func BoolToPtr(b bool) *bool {
	return &b
}

func Int64ToPtr(i int64) *int64 {
	return &i
}

func Int32ToPtr(i int32) *int32 {
	return &i
}

func IntOrStrPtr(v string) *intstr.IntOrString {
	ios := intstr.Parse(v)
	return &ios
}
