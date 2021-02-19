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

package initializecrs

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operator "github.com/tigera/operator/api/v1"
)

var log = logf.Log.WithName("Initialize_CRs")
var TRACE = 7
var DEBUG = 5

func InitializeCRs(ctx context.Context, client client.Client) error {

	for x, _ := range os.Environ() {
		pair := strings.SplitN(x, "=", 2)
		if strings.HasPrefix(x[0], "INITIALIZE_CR_") {
			err := createIfNotExists(ctx, client, x[1])
			if err != nil {
				return fmt.Errorf("Error initializing %s: %v", x[0], err)
			}
		}
	}

	return nil
}

type Metadata struct {
	Name string `yaml: "name"`
}

type resource struct {
	ApiVer string   `yaml: "apiVersion"`
	Kind   string   `yaml: "kind"`
	Meta   metadata `yaml: "metadata"`
}

func createIfNotExists(ctx context.Context, client client.Client, yml string) error {
	x := resource{}

	if err := yaml.Unmarshal([]byte(yml), &x); err != nil {
		return err
	}

	if x.ApiVer != "operator.tigera.io/v1" {
		return fmt.Errorf("Unknown apiVersion %s", x.apiVersion)
	}

	var instance client.Object
	switch x.Kind {
	case "AmazonCloudIntegration":
		instance = &operator.AmazonCloudIntegration{}
	case "APIServer":
		instance = &operator.APIServer{}
	case "Authentication":
		instance = &operator.Authentication{}
	case "Compliance":
		instance = &operator.Compliance{}
	case "ImageSet":
		instance = &operator.ImageSet{}
	case "Installation":
		instance = &operator.Installation{}
	case "IntrusionDetection":
		instance = &operator.IntrusionDetection{}
	case "LogCollector":
		instance = &operator.LogCollector{}
	case "LogStorage":
		instance = &operator.LogStorage{}
	case "ManagementCluster":
		instance = &operator.ManagementCluster{}
	case "ManagementClusterConnection":
		instance = &operator.ManagementClusterConnection{}
	case "Manager":
		instance = &operator.Manager{}
	}

	err := client.Get(ctx, x.Meta.Name, instance)
	if err != nil {
		return nil
	}
	if apierrors.IsNotFound(err) {
	}
}
