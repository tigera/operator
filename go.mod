module github.com/tigera/operator

go 1.16

require (
	github.com/aws/aws-sdk-go v1.19.6
	github.com/cloudflare/cfssl v1.4.1
	github.com/containernetworking/cni v0.8.0
	github.com/elastic/cloud-on-k8s v0.0.0-20200811130517-b53162318c20
	github.com/ghodss/yaml v1.0.0
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/go-logr/logr v0.3.0
	github.com/hashicorp/go-version v1.2.1
	github.com/olivere/elastic/v7 v7.0.6
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/openshift/api v0.0.0-20200923080607-2a18526802e3
	github.com/openshift/library-go v0.0.0-20200924151131-575c4875cdbe
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.48.1
	github.com/r3labs/diff/v2 v2.8.0
	github.com/stretchr/testify v1.6.1
	github.com/tigera/api v0.0.0-20211011084451-556d977afc02
	go.uber.org/zap v1.15.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/api v0.21.0-rc.0
	k8s.io/apiextensions-apiserver v0.19.2
	k8s.io/apimachinery v0.21.0-rc.0
	k8s.io/client-go v0.21.0-rc.0
	k8s.io/kube-aggregator v0.19.2
	sigs.k8s.io/controller-runtime v0.7.0
	sigs.k8s.io/kind v0.11.1 // indirect
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	github.com/go-logr/logr => github.com/go-logr/logr v0.3.0
	github.com/go-logr/zapr => github.com/go-logr/zapr v0.2.0
	//github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.5.1
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v1.0.1
	k8s.io/api => k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.2
	k8s.io/apiserver => k8s.io/apiserver v0.19.2
	k8s.io/client-go => k8s.io/client-go v0.19.2 // Required by prometheus-operator
	k8s.io/klog => k8s.io/klog v1.0.0

	k8s.io/klog/v2 => k8s.io/klog/v2 v2.1.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.7.0
)
