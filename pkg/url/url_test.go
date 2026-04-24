// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package url

import "testing"

func TestParseEndpoint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		endpoint   string
		wantScheme string
		wantHost   string
		wantPort   string
		wantErr    bool
	}{
		{
			name:       "dns host",
			endpoint:   "tcp://syslog.example.com:601",
			wantScheme: "tcp",
			wantHost:   "syslog.example.com",
			wantPort:   "601",
		},
		{
			name:       "ipv4 host",
			endpoint:   "https://1.2.3.4:443",
			wantScheme: "https",
			wantHost:   "1.2.3.4",
			wantPort:   "443",
		},
		{
			name:       "bracketed ipv6 host",
			endpoint:   "https://[fd00::1]:443",
			wantScheme: "https",
			wantHost:   "fd00::1",
			wantPort:   "443",
		},
		{
			name:     "missing port",
			endpoint: "https://example.com",
			wantErr:  true,
		},
		{
			name:     "unbracketed ipv6 host",
			endpoint: "https://fd00::1:443",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotScheme, gotHost, gotPort, err := ParseEndpoint(tc.endpoint)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseEndpoint(%q) expected error, got nil", tc.endpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEndpoint(%q) unexpected error: %v", tc.endpoint, err)
			}
			if gotScheme != tc.wantScheme || gotHost != tc.wantHost || gotPort != tc.wantPort {
				t.Fatalf("ParseEndpoint(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tc.endpoint, gotScheme, gotHost, gotPort, tc.wantScheme, tc.wantHost, tc.wantPort)
			}
		})
	}
}
