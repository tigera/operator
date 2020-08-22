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

// this cli tool initializes and runs the conversion package which converts
// an existing manifest install of Calico into an installation object which represents it.
package main

import (
	"context"
	"fmt"
	"log"

	"gopkg.in/yaml.v2"

	"github.com/tigera/operator/pkg/apis"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/migration/convert"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes/scheme"
	client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := appsv1.AddToScheme(scheme.Scheme); err != nil {
		return err
	}
	if err := apis.AddToScheme(scheme.Scheme); err != nil {
		return err
	}

	config := config.GetConfigOrDie()

	cl, err := client.New(config, client.Options{})
	if err != nil {
		return err
	}

	var i = &operatorv1.Installation{}

	if err := convert.Convert(context.Background(), cl, i); err != nil {
		return err
	}
	if i == nil {
		return fmt.Errorf("no install detected")
	}

	bits, err := yaml.Marshal(i)
	if err != nil {
		return err
	}
	fmt.Println(string(bits))
	return nil
}
