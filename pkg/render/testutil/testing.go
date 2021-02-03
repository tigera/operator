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

package testutil

import (
	"fmt"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func ExpectK8sServiceEpEnvVars(podSpec corev1.PodSpec, host, port string) {
	for _, c := range podSpec.Containers {
		ExpectWithOffset(1, c.Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: host},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: port},
		), fmt.Sprintf("Container %s did not have KUBERENETES_SERVICE_... env vars", c.Name))
	}
	for _, c := range podSpec.InitContainers {
		ExpectWithOffset(1, c.Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: host},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: port},
		), fmt.Sprintf("Init container %s did not have KUBERENETES_SERVICE_... env vars", c.Name))
	}
}
