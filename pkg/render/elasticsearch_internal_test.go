package render

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

func Test_convertQuantityJVMHeapSize(t *testing.T) {
	type args struct {
		q resource.Quantity
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "Conversion from Gi to G", args: args{q: resource.MustParse("2Gi")}, want: "1G"},
		{name: "Conversion from Gi to M", args: args{q: resource.MustParse("3Gi")}, want: "1536M"},
		{name: "Conversion from Mi to M", args: args{q: resource.MustParse("650Mi")}, want: "325M"},
		{name: "Conversion from Mi to K", args: args{q: resource.MustParse("5Mi")}, want: "2560K"},
		{name: "Conversion from Ki to K", args: args{q: resource.MustParse("2500000Ki")}, want: "1250000K"},
		{name: "Conversion from G to K (with rounding)", args: args{q: resource.MustParse("2G")}, want: "976562K"},
		{name: "Conversion from M to K (with rounding)", args: args{q: resource.MustParse("13M")}, want: "6347K"},
		{name: "Conversion from k is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("5k")}, want: "2M"},
		// Below example is 2Gi
		{name: "Conversion from raw number equivalent to Gi to G", args: args{q: resource.MustParse("2147483648")}, want: "1G"},
		// Below example is 5Gi, which ends up translate to M (not G) because using G would result in decimal value
		{name: "Conversion from raw number equivalent to Gi to M", args: args{q: resource.MustParse("5368709120")}, want: "2560M"},
		// Below example is 40Mi
		{name: "Conversion from raw number equivalent to Mi to M", args: args{q: resource.MustParse("41943040")}, want: "20M"},
		// Below example is 20Mi
		{name: "Conversion from raw number equivalent to Mi to K", args: args{q: resource.MustParse("20097152")}, want: "9813K"},
		{name: "Conversion from raw number is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("2000")}, want: "2M"},
		{name: "Conversion from raw number is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("500000")}, want: "2M"},
		{name: "Conversion from decimal is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("5.4")}, want: "2M"},
		{name: "Conversion from Mi is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("1Mi")}, want: "2M"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := memoryQuantityToJVMHeapSize(&tt.args.q); got != tt.want {
				t.Errorf("convertQuantityJVMHeapSize() = %v, want %v", got, tt.want)
			}
		})
	}
}
