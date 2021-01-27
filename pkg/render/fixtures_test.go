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

package render_test

import (
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	v1 "k8s.io/api/core/v1"
)

var complianceServerCertSecret *v1.Secret
var internalManagerTLSSecret *v1.Secret
var voltronTunnelSecret *v1.Secret

func init() {
	dnsNames := dns.GetServiceDNSNames(render.ComplianceServiceName, render.ComplianceNamespace, dns.DefaultClusterDomain)
	complianceServerCertSecret, _ = render.CreateOperatorTLSSecret(
		nil, render.ComplianceServerCertSecret, render.ComplianceServerKeyName, render.ComplianceServerCertName, render.DefaultCertificateDuration, nil, dnsNames...)

	dnsNames = dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
	dnsNames = append(dnsNames, render.ManagerServiceIP)
	internalManagerTLSSecret, _ = render.CreateOperatorTLSSecret(
		nil, render.ManagerInternalTLSSecretName, render.ManagerInternalSecretKeyName, render.ManagerInternalSecretCertName, 825*24*time.Hour, nil, dnsNames...)

	voltronTunnelSecret, _ = render.CreateOperatorTLSSecret(
		nil, render.VoltronTunnelSecretName, render.VoltronTunnelSecretKeyName, render.VoltronTunnelSecretCertName, crypto.DefaultCACertificateLifetimeInDays, nil, render.VoltronDnsName)
}
