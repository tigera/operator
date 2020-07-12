package parser

// ErrIncompatibleCluster indicates that a config option was detected in the existing install
// which Operator does not support.
type ErrIncompatibleCluster struct {
	err string
}

func (e ErrIncompatibleCluster) Error() string {
	return e.err
}
