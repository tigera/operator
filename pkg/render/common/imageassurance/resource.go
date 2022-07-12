// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package imageassurance

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	ConfigurationConfigMapName     = "tigera-image-assurance-config"
	ConfigurationConfigMapOrgIDKey = "organizationID"

	APIEndpoint                           = "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"
	CABundlePath                          = "/certs/bast/tls.crt"
	CAMountPath                           = "/certs/bast"
	ImageAssuranceCertHashAnnotation      = "hash.operator.tigera.io/image-assurance-tls"
	ImageAssuranceAPITokenHashAnnontation = "hash.operator.tigera.io/pod-watcher-image-assurance-api-token"
	ImageAssuranceSecretName              = "tigera-image-assurance-api-cert"
)

// Resources contains all the resource needed for Image Assurance.
type Resources struct {
	ConfigurationConfigMap *corev1.ConfigMap
	TLSSecret              *corev1.Secret
	ImageAssuranceToken    []byte
}
