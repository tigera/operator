module github.com/tigera/operator

go 1.14

require (
	github.com/aws/aws-sdk-go v1.34.23
	github.com/cloudflare/cfssl v1.4.1
	github.com/elastic/cloud-on-k8s v0.0.0-20200526192013-f13b6d26a186
	github.com/go-logr/logr v0.1.0
	github.com/go-openapi/spec v0.19.4
	github.com/hashicorp/go-version v1.2.0
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/openshift/api v3.9.1-0.20190927182313-d4a64ec2cbd8+incompatible
	github.com/openshift/library-go v0.0.0-20190924092619-a8c1174d4ee7
	github.com/pkg/errors v0.8.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.5.1
	github.com/tigera/api v0.0.0-20200311151854-a6d8502444cd
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/kubernetes v1.16.2
)

require (
	github.com/operator-framework/operator-sdk v0.14.1
	k8s.io/api v0.17.2
	k8s.io/apiextensions-apiserver v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kube-aggregator v0.0.0
	k8s.io/kube-openapi v0.0.0-20190918143330-0270cf2f1c1d
	sigs.k8s.io/controller-runtime v0.5.0
)

// Pinned to kubernetes-1.16.2
replace (
	k8s.io/api => k8s.io/api v0.0.0-20191016110408-35e52d86657a
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113550-5357c4baaf65
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004115801-a2eda9f80ab8
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191016112112-5190913f932d
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20191016114015-74ad18325ed5
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016111102-bec269661e48
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20191016115326-20453efc2458
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20191016115129-c07a134afb42
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20191004115455-8e001e5d1894
	k8s.io/component-base => k8s.io/component-base v0.0.0-20191016111319-039242c015a9
	k8s.io/cri-api => k8s.io/cri-api v0.0.0-20190828162817-608eb1dad4ac
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20191016115521-756ffa5af0bd
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20191016112429-9587704a8ad4
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20191016114939-2b2b218dc1df
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20191016114407-2e83b6f20229
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20191016114748-65049c67a58b
	k8s.io/kubectl => k8s.io/kubectl v0.0.0-20191016120415-2ed914427d51
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20191016114556-7841ed97f1b2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20191016115753-cf0698c3a16b
	k8s.io/metrics => k8s.io/metrics v0.0.0-20191016113814-3b1a734dba6e
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20191016112829-06bb3c9d77c9
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

//require (
//	github.com/cloudflare/cfssl v1.4.1
//	github.com/elastic/cloud-on-k8s v0.0.0-20200526192013-f13b6d26a186
//	github.com/go-logr/logr v0.1.0
//	github.com/go-openapi/spec v0.19.0
//	github.com/hashicorp/go-version v1.2.0
//	github.com/onsi/ginkgo v1.10.1
//	github.com/onsi/gomega v1.7.0
//	github.com/openshift/api v3.9.1-0.20190927182313-d4a64ec2cbd8+incompatible
//	github.com/openshift/library-go v0.0.0-20190924092619-a8c1174d4ee7
//	github.com/operator-framework/operator-sdk v0.14.1
//	github.com/pkg/errors v0.8.1
//	github.com/spf13/pflag v1.0.5
//	github.com/stretchr/testify v1.4.0
//	github.com/tigera/api v0.0.0-20200311151854-a6d8502444cd
//	gopkg.in/inf.v0 v0.9.1
//	gopkg.in/yaml.v2 v2.2.8
//	k8s.io/api v0.18.2
//	k8s.io/apiextensions-apiserver v0.17.0
//	k8s.io/apimachinery v0.18.2
//	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
//	k8s.io/cluster-bootstrap v0.18.2 // indirect
//	k8s.io/component-base v0.18.2 // indirect
//	k8s.io/kube-aggregator v0.0.0-20190404125450-f5e124c822d6
//	k8s.io/kube-openapi v0.0.0-20190918143330-0270cf2f1c1d
//	k8s.io/kubernetes v1.14.2
//	sigs.k8s.io/controller-runtime v0.5.0
//)
//
//// Pinned to kubernetes-1.14.1
//replace (
//	// autoneg is a dependency of early versions of operator-sdk (i.e. pre v1.0).
//	// it is no longer hosted on bitbucket.org, so the files are checked in locally and replaced here.
//	bitbucket.org/ww/goautoneg => ./vendor/bitbucket.org/ww/autoneg
//
//	// This is cloud-on-k8s 1.0.1 tag
//	github.com/elastic/cloud-on-k8s => github.com/elastic/cloud-on-k8s v0.0.0-20200526192013-f13b6d26a186
//	k8s.io/api => k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
//	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190409022649-727a075fdec8
//	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
//	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20190409021813-1ec86e4da56c
//	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190409023024-d644b00f3b79
//	k8s.io/client-go => k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
//	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20190409023720-1bc0c81fa51d
//	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190311093542-50b561225d70
//	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20190409022021-00b8e31abe9d
//	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190510232812-a01b7d5d6c22
//	k8s.io/kubernetes => k8s.io/kubernetes v1.14.1
//	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.2.0
//)
//
//replace github.com/operator-framework/operator-lifecycle-manager => github.com/operator-framework/operator-lifecycle-manager v0.0.0-20190605231540-b8a4faf68e36
