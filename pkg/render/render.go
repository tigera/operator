// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package render

import (
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func Render(cr *operator.Installation) []runtime.Object {
	var objs []runtime.Object
	objs = appendNotNil(objs, CustomResourceDefinitions(cr))
	objs = appendNotNil(objs, KubeProxy(cr))
	objs = appendNotNil(objs, Namespaces(cr))
	objs = appendNotNil(objs, Node(cr))
	objs = appendNotNil(objs, KubeControllers(cr))
	objs = appendNotNil(objs, APIServer(cr))
	return objs
}

func appendNotNil(objs []runtime.Object, newObjs []runtime.Object) []runtime.Object {
	for _, x := range newObjs {
		if x != nil {
			objs = append(objs, x)
		}
	}
	return objs
}
