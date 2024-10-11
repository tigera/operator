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

package render

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did
)

var (
	//go:embed gateway_api_crds.yaml
	gatewayAPICRDsYAML string

	yamlDelimiter = "\n---\n"
	lock          sync.Mutex
	cachedObjects []client.Object
)

type yamlKind struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func GatewayAPICRDs(log logr.Logger) []client.Object {
	lock.Lock()
	defer lock.Unlock()

	if len(cachedObjects) == 0 {
		for _, yml := range strings.Split(gatewayAPICRDsYAML, yamlDelimiter) {
			var yamlKind yamlKind
			if err := yaml.Unmarshal([]byte(yml), &yamlKind); err != nil {
				panic(fmt.Sprintf("unable to unmarshal YAML: %v:\n%v\n", err, yml))
			}
			kindStr := yamlKind.APIVersion + "/" + yamlKind.Kind
			if kindStr == "apiextensions.k8s.io/v1/CustomResourceDefinition" {
				obj := &apiextenv1.CustomResourceDefinition{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			}
		}
	}

	gatewayAPICRDs := make([]client.Object, len(cachedObjects))
	for i := range cachedObjects {
		gatewayAPICRDs[i] = cachedObjects[i].DeepCopyObject().(client.Object)
	}

	return gatewayAPICRDs
}
