module github.com/tigera/operator

go 1.16

require (
	github.com/aws/aws-sdk-go v1.25.37
	github.com/cloudflare/cfssl v1.4.1
	github.com/containernetworking/cni v0.8.0
	github.com/elastic/cloud-on-k8s v0.0.0-20210914143041-4f367c381636
	github.com/ghodss/yaml v1.0.0
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/go-logr/logr v0.4.0
	github.com/hashicorp/go-version v1.2.1
	github.com/olivere/elastic/v7 v7.0.6
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.15.0
	github.com/openshift/api v0.0.0-20200923080607-2a18526802e3
	github.com/openshift/library-go v0.0.0-20200924151131-575c4875cdbe
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.52.1
	github.com/r3labs/diff/v2 v2.8.0
	github.com/stretchr/testify v1.7.0
	github.com/tigera/api v0.0.0-20211202170222-d8128d06db71
	go.uber.org/zap v1.19.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.22.3
	k8s.io/apiextensions-apiserver v0.22.3
	k8s.io/apimachinery v0.22.3
	k8s.io/client-go v0.21.7
	k8s.io/kube-aggregator v0.21.7
	sigs.k8s.io/controller-runtime v0.9.7
	sigs.k8s.io/kind v0.11.1 // Do not remove, not used by code but used by build
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	//github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.5.1
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v1.0.1

	github.com/tigera/api => github.com/freecaykes/api v0.0.0-20220201212129-281c51cc19ae

	k8s.io/api => k8s.io/api v0.21.7
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.7
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.7
	k8s.io/apiserver => k8s.io/apiserver v0.21.7
	k8s.io/client-go => k8s.io/client-go v0.21.7 // Required by prometheus-operator
	k8s.io/klog => k8s.io/klog v1.0.0
	k8s.io/klog/v2 => k8s.io/klog/v2 v2.1.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.9.7
)
