module github.com/tigera/operator

go 1.12

require (
	github.com/elastic/cloud-on-k8s v0.0.0-20190924084002-6ce4c9177aec
	github.com/elastic/go-elasticsearch/v7 v7.3.0
	github.com/go-logr/logr v0.1.0
	github.com/go-openapi/spec v0.19.0
	github.com/hashicorp/go-version v1.2.0
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.7.0
	github.com/openshift/api v3.9.1-0.20190927182313-d4a64ec2cbd8+incompatible
	github.com/openshift/library-go v0.0.0-20190924092619-a8c1174d4ee7
	github.com/operator-framework/operator-sdk v0.10.1-0.20190910171846-947a464dbe96
	github.com/spf13/pflag v1.0.3
	github.com/tigera/api v0.0.0-20190901180503-1995fe80fcfb
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190612125737-db0771252981
	k8s.io/apiextensions-apiserver v0.0.0-20190409022649-727a075fdec8
	k8s.io/apimachinery v0.0.0-20190612125636-6a5db36e93ad
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/kube-aggregator v0.0.0-20190404125450-f5e124c822d6
	k8s.io/kube-openapi v0.0.0-20190816220812-743ec37842bf
	sigs.k8s.io/controller-runtime v0.2.1
)

// Pinned to kubernetes-1.14.1
replace (
	// autoneg is a dependency of early versions of operator-sdk (i.e. pre v1.0).
	// it is no longer hosted on bitbucket.org, so the files are checked in locally and replaced here.
	bitbucket.org/ww/goautoneg => ./vendor/bitbucket.org/ww/autoneg
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
