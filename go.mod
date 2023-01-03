module github.com/tigera/operator

go 1.16

require (
	github.com/aws/aws-sdk-go v1.44.106
	github.com/cloudflare/cfssl v1.6.3
	github.com/containernetworking/cni v1.0.1
	github.com/elastic/cloud-on-k8s/v2 v2.0.0-20221014162453-642f9ecd3e2e
	github.com/ghodss/yaml v1.0.0
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/go-logr/logr v1.2.3
	github.com/hashicorp/go-version v1.2.1
	github.com/olivere/elastic/v7 v7.0.6
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.24.2
	github.com/openshift/api v0.0.0-20200923080607-2a18526802e3
	github.com/openshift/library-go v0.0.0-20200924151131-575c4875cdbe
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/api v0.0.0-20220129171754-5c0717447274
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.52.1
	github.com/r3labs/diff/v2 v2.15.1
	github.com/stretchr/testify v1.8.1
	github.com/tigera/api v0.0.0-20220913211214-c3f5117f4f40
	go.uber.org/zap v1.23.0
	golang.org/x/crypto v0.4.0
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.25.3
	k8s.io/apiextensions-apiserver v0.25.3
	k8s.io/apimachinery v0.25.3
	k8s.io/client-go v0.25.3
	k8s.io/kube-aggregator v0.25.3
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed
	sigs.k8s.io/controller-runtime v0.13.0
	sigs.k8s.io/kind v0.11.1 // Do not remove, not used by code but used by build
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v1.0.1

	// Scanners flag anything less than v0.3.8 as having a CVE.
	golang.org/x/text => golang.org/x/text v0.4.0
	k8s.io/apiserver => k8s.io/apiserver v0.25.3
)
