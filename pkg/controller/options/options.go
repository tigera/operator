package options

import v1 "github.com/tigera/operator/api/v1"

// AddOptions are passed to controllers when added to the controller manager. They
// detail options detected by the daemon at startup that some controllers may either
// use to determine if they should run at all, or store them and influence their
// reconciliation loops.
type AddOptions struct {
	DetectedProvider    v1.Provider
	EnterpriseCRDExists bool
	AmazonCRDExists     bool
	LocalDNS            string
}
