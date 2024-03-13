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

const (
	// OperatorCompleteFinalizer is applied by the core controller as part of Installation defaulting to ensure it can
	// clean up resources if the Installation is ever deleted. This Finalizer is only removed after all operator
	// finalization logic has completed.
	OperatorCompleteFinalizer = "tigera.io/operator-cleanup"

	// APIServerFinalizer is added to the Installation by the API server controller when installing the API server so that
	// Calico CNI resources are not removed until the API server controller has had time to properly tear down pods.
	APIServerFinalizer = "operator.tigera.io/apiserver-controller"

	// InstallationControllerFinalizer is added to the Installation by the core Installation controller when installing Calico
	// so that Calico CNI resources are not removed until calico-kube-controllers has had time to properly be torn down.
	InstallationControllerFinalizer = "operator.tigera.io/installation-controller"
)
