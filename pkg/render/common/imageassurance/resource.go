// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	ConfigurationConfigMapName     = "tigera-image-assurance-config"
	ConfigurationConfigMapOrgIDKey = "organizationID"

	APIEndpoint                                         = "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"
	CABundlePath                                        = "/certs/bast/tls.crt"
	CAMountPath                                         = "/certs/bast"
	ImageAssuranceCertHashAnnotation                    = "hash.operator.tigera.io/image-assurance-tls"
	ImageAssuranceRuntimeCleanerAPITokenHashAnnontation = "hash.operator.tigera.io/runtime-cleaner-image-assurance-api-token"
	ImageAssuranceSecretName                            = "tigera-image-assurance-api-cert"
	ScannerCLITokenSecretName                           = "tigera-image-assurance-scanner-cli-token"
	ScannerCLIDownloadURL                               = "https://docs.calicocloud.io/image-assurance/scan-image-registries#start-the-cli-scanner"
)

// Resources contains all the resource needed for Image Assurance.
type Resources struct {
	ConfigurationConfigMap *corev1.ConfigMap
	TLSSecret              *corev1.Secret
	ImageAssuranceToken    []byte
}
