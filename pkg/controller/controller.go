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

package controller

import (
	"github.com/tigera/operator/pkg/controller/options"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// AddToManagerFuncs is a list of functions to add all Controllers to the Manager
// Each func takes the manager as well as a Provider indicating any detected provider,
// as well as a boolean indicating whether we need to start TSEE controllers.
var AddToManagerFuncs []func(manager.Manager, options.AddOptions) error

// AddToManager adds all Controllers to the Manager
func AddToManager(m manager.Manager, opts options.AddOptions) error {
	for _, f := range AddToManagerFuncs {
		if err := f(m, opts); err != nil {
			return err
		}
	}
	return nil
}
