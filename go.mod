module github.com/tigera/operator

go 1.23.1

toolchain go1.23.5

require (
	github.com/aws/aws-sdk-go v1.55.5
	github.com/cloudflare/cfssl v1.6.5
	github.com/containernetworking/cni v1.2.3
	github.com/corazawaf/coraza-coreruleset v0.0.0-20240226094324-415b1017abdc
	github.com/elastic/cloud-on-k8s/v2 v2.14.0
	github.com/envoyproxy/gateway v1.2.6
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/go-logr/logr v1.4.2
	github.com/google/go-cmp v0.6.0
	github.com/hashicorp/go-version v1.7.0
	github.com/olivere/elastic/v7 v7.0.32
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/ginkgo/v2 v2.20.1
	github.com/onsi/gomega v1.34.2
	github.com/openshift/api v0.0.0-20240924220842-3c700b6cb32b
	github.com/openshift/library-go v0.0.0-20240930172803-190f286b06b1
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/api v0.0.0-20240708202104-e3f70b269c2c
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.74.0
	github.com/r3labs/diff/v2 v2.15.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	github.com/tigera/api v0.0.0-20230406222214-ca74195900cb
	github.com/urfave/cli/v3 v3.0.0-beta1
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.32.0
	golang.org/x/net v0.34.0
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.31.2
	k8s.io/apiextensions-apiserver v0.31.2
	k8s.io/apimachinery v0.31.2
	k8s.io/apiserver v0.31.2
	k8s.io/client-go v0.31.2
	k8s.io/kube-aggregator v0.30.5
	sigs.k8s.io/controller-runtime v0.19.1
	sigs.k8s.io/gateway-api v1.2.1
	sigs.k8s.io/kind v0.24.0 // Do not remove, not used by code but used by build
	sigs.k8s.io/yaml v1.4.0
)

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/alessio/shellescape v1.4.2 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/elastic/go-sysinfo v1.13.1 // indirect
	github.com/elastic/go-ucfg v0.8.8 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/emicklei/go-restful/v3 v3.12.1 // indirect
	github.com/evanphx/json-patch v5.9.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.9.0 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-logr/zapr v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/pprof v0.0.0-20240827171923-fa2c70bbbfe5 // indirect
	github.com/google/safetext v0.0.0-20220905092116-b49f7bc46da2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/imdario/mergo v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jinzhu/copier v0.3.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/magefile/mage v1.14.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.60.1 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/spf13/cobra v1.8.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.elastic.co/apm/module/apmzap/v2 v2.6.0 // indirect
	go.elastic.co/apm/v2 v2.6.0 // indirect
	go.elastic.co/fastjson v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/term v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
	gomodules.xyz/jsonpatch/v2 v2.4.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	howett.net/plist v1.0.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240521193020-835d969ad83a // indirect
	k8s.io/utils v0.0.0-20240821151609-f90d01438635 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	github.com/imdario/mergo => github.com/imdario/mergo v0.3.16 // Per advice at https://github.com/darccio/mergo?tab=readme-ov-file#100
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v1.0.1
)
