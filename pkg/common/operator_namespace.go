package common

import (
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/log"
)

var namespace = ""

func init() {
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		namespace = v
		return
	}
	body, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Errorf("Failed to read namespace file: %v", err)
	} else {
		namespace = string(body)
		return
	}

	namespace = "tigera-operator"
}

// OperatorNamespace returns the namespace the operator is running in.
// The value returned is based on the following priority (these are evaluated at startup):
//   If the OPERATOR_NAMESPACE environment variable is non-empty then that is return.
//   If the file /var/run/secrets/kubernetes.io/serviceaccount/namespace is non-empty
//   then the contents is returned.
//   The default "tigera-operator" is returned.
func OperatorNamespace() string {
	return namespace
}
