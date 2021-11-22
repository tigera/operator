package common

import (
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/log"
)

var serviceAccount = ""

func init() {
	v, ok := os.LookupEnv("OPERATOR_SERVICEACCOUNT")
	if ok {
		serviceAccount = v
		return
	}
	body, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Info("Failed to read serviceaccount/namespace file")
	} else {
		serviceAccount = string(body)
		return
	}
	serviceAccount = "tigera-operator"
}

// OperatorServiceAccount returns the ServiceAccount name the operator is running in.
// The value returned is based on the following priority (these are evaluated at startup):
//   If the OPERATOR_SERVICEACCOUNT environment variable is non-empty then that is return.
//   If the file /var/run/secrets/kubernetes.io/serviceaccount/namespace is non-empty
//   then the contents is returned.
//   The default "tigera-operator" is returned.
func OperatorServiceAccount() string {
	return serviceAccount
}
