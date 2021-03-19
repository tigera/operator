package convert

import operatorv1 "github.com/tigera/operator/api/v1"

// handlers are grouped by feature or product and check various
// fields on Calico components to construct a Installation resource that
// represents the currently installed resources.
// Handlers will do any combination of the following:
// - mark incompatible clusters by returning a IncompatibleClusterError
// - carry user config forward by setting the Installation resource according to the installed config
// - mark variables as 'checked' so that the final env var catch-all doesn't throw an 'unexpected env var' error
type handler func(*components, *operatorv1.Installation) error

var handlers = []handler{
	checkTypha,
	handleAddonManager,
	handleNetwork,
	handleIPv6,
	handleCore,
	handleAnnotations,
	handleNodeSelectors,
	handleFelixNodeMetrics,
	handleTyphaMetrics,
	handleCalicoCNI,
	handleNonCalicoCNI,
	handleMTU,
	handleIPPools,
}
