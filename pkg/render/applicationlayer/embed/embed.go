// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package embed

import (
	"embed"
	"fmt"
	"io/fs"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	FS fs.FS
	//go:embed coreruleset
	crsFS embed.FS
)

func init() {
	var err error
	FS, err = fs.Sub(crsFS, "coreruleset")
	if err != nil {
		panic(err)
	}
}

func AsMap() (map[string]string, error) {
	res := make(map[string]string)
	var walkFn fs.WalkDirFunc = func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return err
		}

		if b, err := fs.ReadFile(FS, path); err != nil {
			return err
		} else {
			res[d.Name()] = string(b)
		}
		return nil
	}

	if err := fs.WalkDir(FS, ".", walkFn); err != nil {
		return nil, fmt.Errorf("failed to walk core ruleset files (%w)", err)
	}

	return res, nil
}

func AsConfigMap(name, namespace string) (*corev1.ConfigMap, error) {
	data, err := AsMap()
	if err != nil {
		return nil, err
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}, nil
}
