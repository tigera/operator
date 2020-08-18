package convert

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

type patch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// patches implements Patch.
type patches []patch

func (s *patches) Type() types.PatchType {
	return types.JSONPatchType
}

func (s *patches) Data(obj runtime.Object) ([]byte, error) {
	return json.Marshal(s)
}

func handleFelixVars(c *components) error {
	cn := getContainer(c.node.Spec.Template.Spec, containerCalicoNode)
	if cn == nil {
		return fmt.Errorf("missing calico-node container")
	}
	// loop through all env vars of the form 'FELIX_key=val', and convert them
	// into patches
	p := new(patches)
	for _, env := range cn.Env {
		if !strings.HasPrefix(env.Name, "FELIX_") {
			continue
		}

		// skip any value that was otherwise checked / accounted for somewhere else
		// in the migration code
		if _, ok := c.node.checkedVars[containerCalicoNode].envVars[env.Name]; ok {
			continue
		}

		fval, err := c.node.getEnv(ctx, c.client, containerCalicoNode, env.Name)
		if err != nil {
			return err
		}

		// downcase and remove FELIX_ prefix
		key := strings.ToLower(strings.TrimPrefix(env.Name, "FELIX_"))
		pp, err := patchFromVal(key, *fval)
		if err != nil {
			return err
		}
		*p = append(*p, pp)

	}

	return c.client.Patch(ctx, &crdv1.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}, p)
}

func patchFromVal(key, val string) (patch, error) {
	// since env vars are caps lock, we need to get the correct casing of
	// the given env var. to do this, loop through the felixconfigspec
	// using reflection, finding the struct field where the downcased name
	// matches the downcased env var name.
	fc := reflect.ValueOf(crdv1.FelixConfigurationSpec{})
	for ii := 0; ii < fc.Type().NumField(); ii++ {
		field := fc.Type().Field(ii)

		if strings.ToLower(key) == strings.ToLower(field.Name) {
			fieldName := strings.Split(field.Tag.Get("json"), ",")[0]

			v, err := convert(field.Type, fc, val)
			if err != nil {
				return patch{}, err
			}

			return patch{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/%s", fieldName),
				Value: v,
			}, nil
		}
	}

	return patch{}, fmt.Errorf("unrecognized felix config setting: %v", key)
}

func convert(t reflect.Type, value reflect.Value, val string) (interface{}, error) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return nil, err
		}
		return b, nil

	case reflect.Int:
		i, err := strconv.Atoi(val)
		if err != nil {
			return nil, err
		}
		return i, nil
	case reflect.String:
		return val, nil
	case reflect.Struct:
		switch value.Interface().(type) {
		case *metav1.Duration:
			d, err := time.ParseDuration(val)
			if err != nil {
				return nil, err
			}
			return metav1.Duration{d}, nil
		}
		// IptablesBackend ?
		// *uint32
		// *[]ProtoPort
		// *[]string
		// *RouteTableRange
		// *AWSSrcDstCheckOption
	}

	return nil, fmt.Errorf("unrecognized type: %s", t.Kind())
}
