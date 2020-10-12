module github.com/tigera/operator

go 1.14

require (
	github.com/cloudflare/cfssl v1.4.1
	github.com/containernetworking/cni v0.8.0
	github.com/elastic/cloud-on-k8s v0.0.0-20200924070441-f0b02d0a0553
	github.com/go-logr/logr v0.2.0
	github.com/go-openapi/spec v0.19.4
	github.com/hashicorp/go-version v1.2.1
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.1
	github.com/openshift/api v0.0.0-20200923080607-2a18526802e3
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/tigera/api v0.0.0-20200313151414-d7e747e812b2
	gopkg.in/inf.v0 v0.9.1
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/kube-aggregator v0.19.2
	sigs.k8s.io/controller-runtime v0.6.3
)

require (
	github.com/aws/aws-sdk-go v1.17.7
	github.com/openshift/client-go v0.0.0-20200827190008-3062137373b5 // indirect
	github.com/openshift/library-go v0.0.0-20200924151131-575c4875cdbe
	github.com/operator-framework/operator-sdk v1.0.1
	github.com/robfig/cron v1.2.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
	sigs.k8s.io/kube-storage-version-migrator v0.0.3 // indirect
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	github.com/go-logr/logr => github.com/go-logr/logr v0.1.0
	github.com/go-logr/zapr => github.com/go-logr/zapr v0.1.0
	//github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.3.1
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v1.0.1
	k8s.io/api => k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.2
	k8s.io/apiserver => k8s.io/apiserver v0.19.2
	k8s.io/client-go => k8s.io/client-go v0.19.2 // Required by prometheus-operator
	k8s.io/klog => k8s.io/klog v1.0.0

	k8s.io/klog/v2 => k8s.io/klog/v2 v2.1.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.6.3
)
