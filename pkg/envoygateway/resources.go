// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package envoygateway

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did
)

var (
	//go:embed resources.yaml
	resources string

	yamlDelimiter = "\n---\n"
	lock          sync.Mutex
	cachedObjects []client.Object
)

type yamlKind struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func GetResources(log logr.Logger) []client.Object {
	lock.Lock()
	defer lock.Unlock()

	if len(cachedObjects) == 0 {
		for _, yml := range strings.Split(resources, yamlDelimiter) {
			var yamlKind yamlKind
			if err := yaml.Unmarshal([]byte(yml), &yamlKind); err != nil {
				panic(fmt.Sprintf("unable to unmarshal YAML: %v:\n%v\n", err, yml))
			}
			kindStr := yamlKind.APIVersion + "/" + yamlKind.Kind
			log.Info(kindStr)
			switch kindStr {
			case "apiextensions.k8s.io/v1/CustomResourceDefinition":
				obj := &apiextenv1.CustomResourceDefinition{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "apps/v1/Deployment":
				obj := &appsv1.Deployment{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "batch/v1/Job":
				obj := &batchv1.Job{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "rbac.authorization.k8s.io/v1/ClusterRole":
				obj := &rbacv1.ClusterRole{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "rbac.authorization.k8s.io/v1/ClusterRoleBinding":
				obj := &rbacv1.ClusterRoleBinding{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "rbac.authorization.k8s.io/v1/Role":
				obj := &rbacv1.Role{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "rbac.authorization.k8s.io/v1/RoleBinding":
				obj := &rbacv1.RoleBinding{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "v1/ConfigMap":
				obj := &v1.ConfigMap{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "v1/Namespace":
				obj := &v1.Namespace{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "v1/Service":
				obj := &v1.Service{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "v1/ServiceAccount":
				obj := &v1.ServiceAccount{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			case "/":
				// No-op.
			default:
				panic(fmt.Sprintf("unhandled type %v", kindStr))
			}
		}
	}

	resources := make([]client.Object, len(cachedObjects))
	for i := range cachedObjects {
		resources[i] = cachedObjects[i].DeepCopyObject().(client.Object)
	}

	return resources
}
