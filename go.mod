module github.com/tigera/operator

go 1.12

require (
	github.com/cloudflare/cfssl v1.4.1
	github.com/containernetworking/cni v0.8.0
	github.com/elastic/cloud-on-k8s v0.0.0-20200204083752-bcb7468838a8
	github.com/go-logr/logr v0.1.0
	github.com/go-openapi/spec v0.19.0
	github.com/hashicorp/go-version v1.2.0
	github.com/juju/errors v0.0.0-20200330140219-3fe23663418f
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/openshift/api v3.9.1-0.20190927182313-d4a64ec2cbd8+incompatible
	github.com/openshift/library-go v0.0.0-20190924092619-a8c1174d4ee7
	github.com/operator-framework/operator-sdk v0.18.1
	github.com/pkg/errors v0.8.1
	github.com/projectcalico/cni-plugin v3.8.9+incompatible
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	github.com/tigera/api v0.0.0-20200311151854-a6d8502444cd
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.18.2
	k8s.io/apiextensions-apiserver v0.0.0-20190918161926-8f644eb6e783
	k8s.io/apimachinery v0.18.2
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/cluster-bootstrap v0.18.2 // indirect
	k8s.io/component-base v0.18.2 // indirect
	k8s.io/kube-aggregator v0.0.0-20190404125450-f5e124c822d6
	k8s.io/kube-openapi v0.0.0-20190918143330-0270cf2f1c1d
	k8s.io/kubernetes v1.14.2
	sigs.k8s.io/controller-runtime v0.4.0
)

// Pinned to kubernetes-1.14.1
replace (
	// This is cloud-on-k8s 1.0.1 tag
	github.com/elastic/cloud-on-k8s => github.com/elastic/cloud-on-k8s v0.0.0-20200204083752-bcb7468838a8
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v0.10.1-0.20190910171846-947a464dbe96
	k8s.io/api => k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190409022649-727a075fdec8
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20190409021813-1ec86e4da56c
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190409023024-d644b00f3b79
	k8s.io/client-go => k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20190409023720-1bc0c81fa51d
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190311093542-50b561225d70
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20190409022021-00b8e31abe9d
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190510232812-a01b7d5d6c22
	k8s.io/kubernetes => k8s.io/kubernetes v1.14.1
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.2.0
)

replace github.com/operator-framework/operator-lifecycle-manager => github.com/operator-framework/operator-lifecycle-manager v0.0.0-20190605231540-b8a4faf68e36
