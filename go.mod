module github.com/tigera/operator

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/coreos/go-semver v0.2.0
	github.com/coreos/prometheus-operator v0.29.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v0.1.0
	github.com/go-logr/zapr v0.1.1
	github.com/go-openapi/spec v0.19.0
	github.com/hashicorp/go-version v1.2.0
	github.com/iancoleman/strcase v0.0.0-20180726023541-3605ed457bf7
	github.com/markbates/inflect v1.0.4
	github.com/martinlindhe/base36 v0.0.0-20180729042928-5cda0030da17
	github.com/mattbaird/jsonpatch v0.0.0-20171005235357-81af80346b1a
	github.com/mitchellh/go-homedir v1.1.0
	github.com/onsi/ginkgo v1.7.0
	github.com/onsi/gomega v1.4.3
	github.com/openshift/api v0.0.0-20190613122633-5114e14c97ff
	github.com/openshift/library-go v0.0.0-20190919191909-cabfcc42d41e
	github.com/operator-framework/operator-lifecycle-manager v0.0.0-20190128024246-5eb7ae5bdb7a
	github.com/operator-framework/operator-sdk v0.10.0
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	github.com/rogpeppe/go-internal v1.3.0
	github.com/sergi/go-diff v1.0.0
	github.com/sirupsen/logrus v1.4.1
	github.com/spf13/afero v1.2.2
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.3.0
	github.com/tigera/api v0.0.0-20190901180503-1995fe80fcfb
	go.uber.org/zap v1.9.1
	golang.org/x/tools v0.0.0-20190408170212-12dd9f86f350
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190612125737-db0771252981
	k8s.io/apiextensions-apiserver v0.0.0-20190228180357-d002e88f6236
	k8s.io/apimachinery v0.0.0-20190612125636-6a5db36e93ad
	k8s.io/cli-runtime v0.0.0-20181213153952-835b10687cb6
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/code-generator v0.0.0-20181203235156-f8cba74510f3
	k8s.io/gengo v0.0.0-20190327210449-e17681d19d3a
	k8s.io/helm v2.13.1+incompatible
	k8s.io/klog v0.3.1
	k8s.io/kube-aggregator v0.0.0-20181213152105-1e8cd453c474
	k8s.io/kube-openapi v0.0.0-20190320154901-5e45bb682580
	k8s.io/kube-state-metrics v1.6.0
	k8s.io/kubernetes v1.11.8-beta.0.0.20190124204751-3a10094374f2
	sigs.k8s.io/controller-runtime v0.1.10
	sigs.k8s.io/controller-tools v0.0.0-20190411181648-9d55346c2bde
)

// Pinned to kubernetes-1.13.4
replace (
	git.apache.org/thrift.git => github.com/apache/thrift v0.12.0
	k8s.io/api => k8s.io/api v0.0.0-20190222213804-5cb15d344471
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190228180357-d002e88f6236
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190221213512-86fb29eff628
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20190228174905-79427f02047f
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190228180923-a9e421a79326
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190228174230-b40b2a5939e4
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20181117043124-c2090bec4d9b
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20190228175259-3e0149950b0e
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20180711000925-0cf8f7e6ed1d
	k8s.io/kubernetes => k8s.io/kubernetes v1.13.4
)
