package convert

// handlers are grouped by feature or product and check various
// fields on Calico components to construct a Installation resource that
// represents the currently install resources.
// Handlers will do any combination of the following:
// - mark incompatible clusters by returning a IncompatibleClusterError
// - carry user config forward by setting the Installation resource according to their installed config
// - mark variables as 'checked' so that the final env var catch-all doesn't throw an 'unexpected env var' error
type handler func(*components, *Installation) error

var handlers = []handler{
	handleNetwork,
	handleCore,
	handleAnnotations,
	handleNodeSelectors,
	handleFelixNodeMetrics,
	handleCalicoCNI,
	handleNonCalicoCNI,
	handleMTU,
	handleIPPool,
}
