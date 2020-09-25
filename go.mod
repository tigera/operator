module github.com/tigera/operator

go 1.14

require (
	github.com/aws/aws-sdk-go v1.34.23
	github.com/cloudflare/cfssl v1.4.1
	github.com/elastic/cloud-on-k8s v0.0.0-20200526192013-f13b6d26a186
	//github.com/go-logr/logr v0.2.0
	github.com/go-openapi/spec v0.19.4
	github.com/hashicorp/go-version v1.2.0
	github.com/onsi/ginkgo v1.12.0
	github.com/onsi/gomega v1.9.0
	github.com/openshift/api v3.9.1-0.20190927182313-d4a64ec2cbd8+incompatible
	github.com/openshift/library-go v0.0.0-20190924092619-a8c1174d4ee7
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.5.1
	github.com/tigera/api v0.0.0-20200311151854-a6d8502444cd
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.2.8
)

// Operator SDK version pins
require (
	github.com/go-logr/logr v0.1.0
	github.com/operator-framework/operator-sdk v0.18.2
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.18.8
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kube-aggregator v0.18.8
	k8s.io/kube-openapi v0.0.0-20200410145947-61e04a5be9a6
	sigs.k8s.io/controller-runtime v0.6.0
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.3.1
	k8s.io/api => k8s.io/api v0.18.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.2
	k8s.io/client-go => k8s.io/client-go v0.18.2 // Required by prometheus-operator
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.6.0
)
