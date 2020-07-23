package convert

// ErrIncompatibleCluster indicates that a config option was detected in the existing install
// which Operator does not support.
type ErrIncompatibleCluster struct {
	err string
}

func (e ErrIncompatibleCluster) Error() string {
	return e.err
}

type ErrContainerNotFound struct {
	err string
}

func (e ErrContainerNotFound) Error() string {
	return e.err
}

func IsContainerNotFound(e error) bool {
	_, ok := e.(ErrContainerNotFound)
	return ok
}
