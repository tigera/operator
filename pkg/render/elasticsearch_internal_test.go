// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		{name: "Conversion from Gi to G", args: args{q: resource.MustParse("3Gi")}, want: "1G"},
		{name: "Conversion from Gi to K (with rounding)", args: args{q: resource.MustParse("4Gi")}, want: "1398101K"},
		{name: "Conversion from Mi to M", args: args{q: resource.MustParse("975Mi")}, want: "325M"},
		{name: "Conversion from Mi to K (with rounding)", args: args{q: resource.MustParse("10Mi")}, want: "3413K"},
		{name: "Conversion from Ki to K", args: args{q: resource.MustParse("2400000Ki")}, want: "800000K"},
		{name: "Conversion from G to K (with rounding)", args: args{q: resource.MustParse("4G")}, want: "1302083K"},
		{name: "Conversion from M to K (with rounding)", args: args{q: resource.MustParse("13M")}, want: "4231K"},
		{name: "Conversion from k is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("5k")}, want: "2M"},
		{name: "Conversion from Gi is above maximum limit (26 gigabytes)", args: args{q: resource.MustParse("96Gi")}, want: "26G"},
		// Below example is 3Gi
		{name: "Conversion from raw number equivalent to Gi to G", args: args{q: resource.MustParse("3221225472")}, want: "1G"},
		// Below example is 5Gi, which ends up translate to K (not G) because using G would result in decimal value
		{name: "Conversion from raw number equivalent to Gi to M", args: args{q: resource.MustParse("5368709120")}, want: "1747626K"},
		// Below example is 20Mi
		{name: "Conversion from raw number equivalent to Mi to K", args: args{q: resource.MustParse("20971520")}, want: "6826K"},
		{name: "Conversion from raw number is below minimum limit (2 megabytes)", args: args{q: resource.MustParse("2000")}, want: "2M"},
		{name: "Conversion from raw number is above maximum limit (26 gigabytes)", args: args{q: resource.MustParse("500000000000")}, want: "26G"},
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
