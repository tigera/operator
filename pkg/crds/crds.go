// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package crds

import (
	"embed"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"

	// gopkg.in/yaml.v2 didn't parse all the fields but the ghodss package did
	"github.com/ghodss/yaml"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	opv1 "github.com/tigera/operator/api/v1"
)

var (
	//go:embed calico
	calicoCRDFiles embed.FS
	//go:embed enterprise
	enterpriseCRDFiles embed.FS
	//go:embed operator/*
	operatorCRDFiles embed.FS

	yamlDelimRe       *regexp.Regexp
	calicoOprtrCRDsRe *regexp.Regexp
	lock              sync.Mutex
	calicoCRDs        []*apiextenv1.CustomResourceDefinition
	enterpriseCRDs    []*apiextenv1.CustomResourceDefinition
)

func init() {
	yamlDelimRe = regexp.MustCompile(`\n---`)

	calicoCRDNames := []string{"installation", "apiserver", "imageset", "tigerastatus"}
	calicoOprtrCRDsRe = regexp.MustCompile(fmt.Sprintf("(%s)", strings.Join(calicoCRDNames, "|")))
}

func GetCalicoCRDSource() map[string][]byte {
	ret := map[string][]byte{}
	entries, err := calicoCRDFiles.ReadDir("calico")
	if err != nil {
		panic(fmt.Sprintf("Failed to read Calico CRDs: %v", err))
	}

	for _, entry := range entries {
		b, err := calicoCRDFiles.ReadFile(path.Join("calico", entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read Calico CRD %s: %v", entry.Name(), err))
		}

		if len(yamlDelimRe.FindAllString(string(b), -1)) > 1 {
			panic(fmt.Sprintf("Too many yaml delimiters in Calico CRD %s", entry.Name()))
		}

		ret[entry.Name()] = yamlDelimRe.ReplaceAll(b, []byte("\n"))
	}

	return ret
}

func GetEnterpriseCRDSource() map[string][]byte {
	ret := map[string][]byte{}
	entries, err := enterpriseCRDFiles.ReadDir("enterprise")
	if err != nil {
		panic(fmt.Sprintf("Failed to read Enterprise CRDs: %v", err))
	}

	for _, entry := range entries {
		b, err := enterpriseCRDFiles.ReadFile(path.Join("enterprise", entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read Enterprise CRD %s: %v", entry.Name(), err))
		}

		if len(yamlDelimRe.FindAllString(string(b), -1)) > 1 {
			panic(fmt.Sprintf("Too many yaml delimiters in Enterprise CRD %s", entry.Name()))
		}

		ret[entry.Name()] = yamlDelimRe.ReplaceAll(b, []byte("\n"))
	}

	return ret
}

func GetOperatorCRDSource(variant opv1.ProductVariant) map[string][]byte {
	ret := map[string][]byte{}
	entries, err := operatorCRDFiles.ReadDir("operator")
	if err != nil {
		panic(fmt.Sprintf("Failed to read Operator CRDs: %v", err))
	}

	for _, entry := range entries {
		if variant == opv1.Calico {
			if !calicoOprtrCRDsRe.MatchString(entry.Name()) {
				continue
			}
		}

		b, err := operatorCRDFiles.ReadFile(path.Join("operator", entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read Operator CRD %s: %v", entry.Name(), err))
		}

		if len(yamlDelimRe.FindAllString(string(b), -1)) > 1 {
			panic(fmt.Sprintf("Too many yaml delimiters in Operator CRD %s", entry.Name()))
		}

		ret[entry.Name()] = yamlDelimRe.ReplaceAll(b, []byte("\n"))
	}

	return ret
}

func GetCRDs(variant opv1.ProductVariant) []*apiextenv1.CustomResourceDefinition {
	lock.Lock()
	defer lock.Unlock()

	if variant == opv1.Calico {
		if len(calicoCRDs) == 0 {
			crdyamls := GetCalicoCRDSource()
			for _, yml := range crdyamls {

				crd := &apiextenv1.CustomResourceDefinition{}
				err := yaml.Unmarshal(yml, crd)
				if err != nil {
					fmt.Println(fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, crd.Spec.Group))
					fmt.Println(err)
					return calicoCRDs
				}
				crd.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, crd.Spec.Group)
				calicoCRDs = append(calicoCRDs, crd)
			}
			crdyamls = GetOperatorCRDSource(variant)
			for _, yml := range crdyamls {
				crd := &apiextenv1.CustomResourceDefinition{}
				yaml.Unmarshal(yml, crd)
				crd.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, crd.Spec.Group)
				calicoCRDs = append(calicoCRDs, crd)
			}
		}
		return calicoCRDs
	} else {
		if len(enterpriseCRDs) == 0 {
			crdyamls := GetEnterpriseCRDSource()
			for _, yml := range crdyamls {
				crd := &apiextenv1.CustomResourceDefinition{}
				yaml.Unmarshal(yml, crd)
				crd.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, crd.Spec.Group)
				enterpriseCRDs = append(enterpriseCRDs, crd)
			}
			crdyamls = GetOperatorCRDSource(variant)
			for _, yml := range crdyamls {
				crd := &apiextenv1.CustomResourceDefinition{}
				yaml.Unmarshal(yml, crd)
				crd.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, crd.Spec.Group)
				enterpriseCRDs = append(enterpriseCRDs, crd)
			}
		}
		return enterpriseCRDs
	}
}

// ToRuntimeObjects converts the given list of CRDs to a list of client.Objects
func ToRuntimeObjects(crds ...*apiextenv1.CustomResourceDefinition) []client.Object {
	var objs []client.Object
	for _, crd := range crds {
		if crd == nil {
			continue
		}
		objs = append(objs, crd)
	}
	return objs
}
