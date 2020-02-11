package mock

import (
	"github.com/stretchr/testify/mock"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type Controller struct {
	mock.Mock
}

func (m *Controller) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	args := m.Called(req)
	result := args.Get(0).(reconcile.Result)

	if args.Get(1) == nil {
		return result, nil
	}

	return result, args.Error(1)
}

func (m *Controller) Watch(src source.Source, eventHandler handler.EventHandler, predicates ...predicate.Predicate) error {
	defer func() {
		_ = src
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	args := m.Called(src, eventHandler, predicates)
	if args.Get(0) == nil {
		return nil
	}

	return args.Error(1)
}

func (m *Controller) Start(stop <-chan struct{}) error {
	args := m.Called(stop)
	if args.Get(0) == nil {
		return nil
	}

	return args.Error(1)
}
