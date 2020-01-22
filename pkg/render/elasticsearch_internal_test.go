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
		{name: "Conversion from G to raw number", args: args{q: resource.MustParse("2G")}, want: "1000000000"},
		{name: "Conversion from M to raw number", args: args{q: resource.MustParse("13M")}, want: "6500000"},
		{name: "Conversion from k to raw number", args: args{q: resource.MustParse("5k")}, want: "2500"},
		{name: "Conversion from raw to raw number", args: args{q: resource.MustParse("2000")}, want: "1k"},
		{name: "Conversion from raw to raw number", args: args{q: resource.MustParse("500000")}, want: "250000"},
		{name: "Conversion from decimal to raw number", args: args{q: resource.MustParse("5.4")}, want: "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := memoryQuantityToJVMHeapSize(&tt.args.q); got != tt.want {
				t.Errorf("convertQuantityJVMHeapSize() = %v, want %v", got, tt.want)
			}
		})
	}
}
