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

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
)

func TestIsReleaseBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		prefix string
		branch string
		want   bool
	}{
		// Default prefix "release"
		{"release", "release-v1.43", true},
		{"release", "release-v1.0", true},
		{"release", "release-v10.20", true},
		{"release", "master", false},
		{"release", "main", false},
		{"release", "release-v1.43.1", false},
		{"release", "release-v1", false},
		{"release", "release-1.43", false},
		{"release", "feature/release-v1.43", false},
		{"release", "release-v1.43-rc1", false},
		{"release", "", false},

		// Custom prefix
		{"rel", "rel-v1.43", true},
		{"rel", "release-v1.43", false},

		// Prefix with regex metacharacters should be escaped
		{"release.test", "release.test-v1.43", true},
		{"release.test", "releasextest-v1.43", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.prefix, tt.branch), func(t *testing.T) {
			t.Parallel()
			got, err := isReleaseBranch(tt.prefix, tt.branch)
			if err != nil {
				t.Fatalf("isReleaseBranch(%q, %q) unexpected error: %v", tt.prefix, tt.branch, err)
			}
			if got != tt.want {
				t.Fatalf("isReleaseBranch(%q, %q) = %v, want %v", tt.prefix, tt.branch, got, tt.want)
			}
		})
	}
}

func TestDevTagVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stream       string
		devSuffix    string
		wantTag      string
		wantParseErr bool
	}{
		{"v1.43", "0.dev", "v1.44.0-0.dev", false},
		{"v1.0", "0.dev", "v1.1.0-0.dev", false},
		{"v10.20", "0.dev", "v10.21.0-0.dev", false},
		{"v0.1", "0.dev", "v0.2.0-0.dev", false},
		{"invalid", "0.dev", "", true},
		{"v1", "0.dev", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.stream, func(t *testing.T) {
			t.Parallel()
			version, err := semver.Parse(fmt.Sprintf("%s.0", strings.TrimPrefix(tt.stream, "v")))
			if tt.wantParseErr {
				if err == nil {
					t.Fatalf("expected parse error for stream %q, got nil", tt.stream)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected parse error for stream %q: %v", tt.stream, err)
			}
			if err := version.IncrementMinor(); err != nil {
				t.Fatalf("unexpected IncrementMinor error: %v", err)
			}
			got := fmt.Sprintf("v%s-%s", version.String(), tt.devSuffix)
			if got != tt.wantTag {
				t.Fatalf("dev tag for stream %q = %q, want %q", tt.stream, got, tt.wantTag)
			}
		})
	}
}

func TestRefExistsInRemote(t *testing.T) {
	t.Parallel()
	// Simulated ls-remote output
	lsRemoteOutput := "abc123\trefs/heads/release-v1.43\ndef456\trefs/tags/v3.30\nghi789\trefs/tags/v3.30^{}\njkl012\trefs/heads/release/v1.2"

	tests := []struct {
		ref  string
		want bool
	}{
		{"release-v1.43", true},
		{"v3.30", true},
		{"v3.3", false}, // should not match partial
		{"v3.30^{}", true},
		{"release-v1.4", false},
		{"nonexistent", false},
		{"release/v1.2", true}, // ref with slash
		{"v1.2", false},        // should not match partial of slashed ref
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			t.Parallel()
			got := refExistsInRemote(lsRemoteOutput, tt.ref)
			if got != tt.want {
				t.Fatalf("refExistsInRemote(output, %q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestValidateStreamFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stream string
		want   bool
	}{
		{"v1.43", true},
		{"v1.0", true},
		{"v10.20", true},
		{"v0.1", true},
		{"1.43", false},
		{"v1.43.1", false},
		{"v1", false},
		{"vX.Y", false},
		{"master", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.stream), func(t *testing.T) {
			t.Parallel()
			got, err := isValidStream(tt.stream)
			if err != nil {
				t.Fatalf("isValidStreamFormat(%q) unexpected error: %v", tt.stream, err)
			}
			if got != tt.want {
				t.Fatalf("isValidStreamFormat(%q) = %v, want %v", tt.stream, got, tt.want)
			}
		})
	}
}
