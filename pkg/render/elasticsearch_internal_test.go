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
		// Case where unit suffix was left off the value
		{name: "Conversion from missing suffix", args: args{q: resource.MustParse("5")}, want: "2"},
		// Case where unit suffix is invalid (missing the "i")
		{name: "Conversion from invalid suffix G", args: args{q: resource.MustParse("3G")}, want: "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertQuantityToJVMHeapSize(&tt.args.q); got != tt.want {
				t.Errorf("convertQuantityJVMHeapSize() = %v, want %v", got, tt.want)
			}
		})
	}
}
