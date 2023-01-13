// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package cloudrbac

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	APIEndpoint        = "https://cc-rbac-api.calico-cloud-rbac.svc:8443"
	CABundlePath       = "/certs/cloud-rbac/tls.crt"
	CAMountPath        = "/certs/cloud-rbac"
	CertHashAnnotation = "hash.operator.tigera.io/cloud-rbac-cert"
	TLSSecretName      = "calico-cloud-rbac-tls"
)

// Resources contains the information needed for configuring tls & voltron for calico-cloud-rbac.
type Resources struct {
	NamespaceName string
	ServiceName   string
	TLSSecret     *corev1.Secret
}
