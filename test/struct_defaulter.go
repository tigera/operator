package test

import (
	"fmt"
	"reflect"
)

const (
	DefaultNonZeroInt64   int64   = 1
	DefaultNonZeroUint64  uint64  = 1
	DefaultNonZeroFloat64 float64 = 1
	DefaultNonZeroString  string  = "not-zero"
	DefaultNonZeroBool    bool    = true
)

type NonZeroDefaultOption func(defaulter *nonZeroValueDefaulter)

func WithInterfaceImplementations(ifaceImpls map[string]interface{}) NonZeroDefaultOption {
	return func(defaulter *nonZeroValueDefaulter) {
		defaulter.ifaceImpls = ifaceImpls
	}
}

type ValueDefaulter interface {
	SetDefault(interface{}) error
}

type nonZeroValueDefaulter struct {
	ifaceImpls map[string]interface{}
}

// NewNonZeroStructDefaulter creates an implementation of the ValueDefaulter that
func NewNonZeroStructDefaulter(options ...NonZeroDefaultOption) ValueDefaulter {
	defaulter := &nonZeroValueDefaulter{}
	for _, option := range options {
		option(defaulter)
	}
	return defaulter
}

func (defaulter *nonZeroValueDefaulter) SetDefault(strct interface{}) error {
	return defaulter.setDefaultValue(reflect.ValueOf(strct).Elem())
}

func (defaulter *nonZeroValueDefaulter) setDefaultValue(value reflect.Value) error {
	if !value.CanSet() {
		return nil
	}

	switch value.Kind() {
	case reflect.Ptr:
		p := reflect.New(value.Type().Elem())
		if err := defaulter.setDefaultValue(p.Elem()); err != nil {
			return err
		}

		value.Set(p)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			f := value.Field(i)
			if err := defaulter.setDefaultValue(f); err != nil {
				return err
			}
		}
	case reflect.Interface:
		ifaceName := value.Type().Name()
		if impl, exists := defaulter.ifaceImpls[ifaceName]; exists {
			implValue := reflect.New(reflect.TypeOf(impl))
			if err := defaulter.setDefaultValue(implValue.Elem()); err != nil {
				return err
			}
			value.Set(implValue)
		} else {
			return fmt.Errorf("no implementation for interface '%s'", value.Type().Name())
		}
	case reflect.Slice:
		v2 := reflect.New(value.Type().Elem())
		if err := defaulter.setDefaultValue(v2.Elem()); err != nil {
			return err
		}

		value.Set(reflect.Append(value, v2.Elem()))
	case reflect.Map:
		mapKey := reflect.New(value.Type().Key())
		mapValue := reflect.New(value.Type().Elem())
		if err := defaulter.setDefaultValue(mapKey.Elem()); err != nil {
			return err
		}

		if err := defaulter.setDefaultValue(mapValue.Elem()); err != nil {
			return err
		}

		m := reflect.MakeMap(value.Type())
		m.SetMapIndex(mapKey.Elem(), mapValue.Elem())

		value.Set(m)
	case reflect.Chan:
		value.Set(reflect.MakeChan(value.Type(), 1))
	default:
		if err := setPrimitive(value); err != nil {
			return err
		}
	}

	return nil
}

func setPrimitive(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Int:
		fallthrough
	case reflect.Int8:
		fallthrough
	case reflect.Int16:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int64:
		v.SetInt(DefaultNonZeroInt64)
	case reflect.Uint:
		fallthrough
	case reflect.Uint8:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Uint32:
		fallthrough
	case reflect.Uint64:
		v.SetUint(DefaultNonZeroUint64)
	case reflect.Float32:
		fallthrough
	case reflect.Float64:
		v.SetFloat(DefaultNonZeroFloat64)
	case reflect.String:
		v.SetString(DefaultNonZeroString)
	case reflect.Bool:
		v.SetBool(DefaultNonZeroBool)
	default:
		return fmt.Errorf("unknown type %s", v.Kind())
	}

	return nil
}
