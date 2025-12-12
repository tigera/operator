// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCalicoConfigVersions(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		fn := "calico-version.yaml"
		full := filepath.Join(td, fn)
		content := "title: v3.25.0\n"
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write version file: %v", err)
		}

		got, err := calicoConfigVersions(td, fn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := CalicoVersion{Title: "v3.25.0"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("retrieved version mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("read error", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		_, err := calicoConfigVersions(td, "nonexistent.yaml")
		if err == nil {
			t.Fatalf("expected error reading nonexistent file, got nil")
		}
		if !strings.Contains(err.Error(), "reading version file") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("unmarshal error", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		fn := "bad.yaml"
		full := filepath.Join(td, fn)
		// invalid YAML that will cause unmarshal to fail for expected struct
		if err := os.WriteFile(full, []byte(":::: not yaml :::"), 0o644); err != nil {
			t.Fatalf("failed to write bad yaml file: %v", err)
		}

		_, err := calicoConfigVersions(td, fn)
		if err == nil {
			t.Fatalf("expected unmarshal error, got nil")
		}
		if !strings.Contains(err.Error(), "unmarshaling version file") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

func TestReleaseVersions(t *testing.T) {
	t.Parallel()

	t.Run("local", func(t *testing.T) {
		t.Parallel()
		calicoVer := "v3.25.0"
		enterpriseVer := "v3.25.0-1.0"
		dir := fakeOperatorRepo(t, calicoVer, enterpriseVer)

		versions, err := calicoVersions(mainRepo, dir, "v1.2.3", true)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		checkReleaseVersions(t, versions, calicoVer, enterpriseVer)
	})

	t.Run("local with no rootDir", func(t *testing.T) {
		t.Parallel()

		_, err := calicoVersions(mainRepo, "", "v1.2.3", true)
		if err == nil {
			t.Fatalf("expected error for missing rootDir, got nil")
		}
		if !strings.Contains(err.Error(), "rootDir must be specified when using local flag") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("local with development calico version", func(t *testing.T) {
		t.Parallel()
		dir := fakeOperatorRepo(t, "master", "master")

		_, err := calicoVersions(mainRepo, dir, "v1.2.3", true)
		if err == nil {
			t.Fatalf("expected error for invalid calico version, got nil")
		}
		if !strings.Contains(err.Error(), "the Calico version specified (master) is not a valid release version") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("local with development enterprise version", func(t *testing.T) {
		t.Parallel()
		calicoVer := "v3.25.0"
		enterpriseVer := "release-calient-v3.20"
		dir := fakeOperatorRepo(t, calicoVer, enterpriseVer)

		versions, err := calicoVersions(mainRepo, dir, "v1.2.3", true)
		if err != nil {
			t.Fatalf("expected no error when enterprise missing, got: %v", err)
		}
		checkReleaseVersions(t, versions, calicoVer, "")
	})
}

func TestIsReleaseVersionFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "v3.25.0",
			want:    true,
		},
		{
			version: "v3.25.0-rc1",
			want:    false,
		},
		{
			version: "v3.25.0-1.0",
			want:    false,
		},
		{
			version: "3.25.0-1.0-rc1",
			want:    false,
		},
		{
			version: "not-a-version",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := isReleaseVersionFormat(tc.version)
			if err != nil {
				t.Fatalf("isReleaseVersionFormat(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isReleaseVersionFormat(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestIsEnterpriseReleaseVersionFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "v3.25.0",
			want:    true,
		},
		{
			version: "v3.25.0-rc1",
			want:    false,
		},
		{
			version: "v3.25.0-1.0",
			want:    true,
		},
		{
			version: "3.25.0-1.0-rc1",
			want:    false,
		},
		{
			version: "not-a-version",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := isEnterpriseReleaseVersionFormat(tc.version)
			if err != nil {
				t.Fatalf("isEnterpriseReleaseVersionFormat(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isEnterpriseReleaseVersionFormat(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func fakeOperatorRepo(t testing.TB, calicoVer, enterpriseVer string) string {
	t.Helper()
	td := t.TempDir()

	// Simulate a git repository by creating a .git dir.
	if _, err := runCommandInDir(td, "git", []string{"init"}, nil); err != nil {
		t.Fatalf("failed to init dir (%s) as git repo: %v", td, err)
	}

	// Create config dir
	if err := os.MkdirAll(filepath.Join(td, configDir), os.ModePerm); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Create calico version file
	calicoContent := fmt.Sprintf("title: %s\n", calicoVer)
	if err := os.WriteFile(filepath.Join(td, calicoConfig), []byte(calicoContent), 0o644); err != nil {
		t.Fatalf("failed to write calico version file: %v", err)
	}
	// Create enterprise version file
	enterpriseContent := fmt.Sprintf("title: %s\n", enterpriseVer)
	if err := os.WriteFile(filepath.Join(td, enterpriseConfig), []byte(enterpriseContent), 0o644); err != nil {
		t.Fatalf("failed to write enterprise version file: %v", err)
	}
	return td
}

func checkReleaseVersions(t testing.TB, got map[string]string, wantCalicoVer, wantEnterpriseVer string) {
	t.Helper()
	want := map[string]string{
		"Calico": wantCalicoVer,
	}
	if wantEnterpriseVer != "" {
		want["Calico Enterprise"] = wantEnterpriseVer
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("releaseVersions() mismatch (-want +got):\n%s", diff)
	}
}

func TestAddTrailingSlash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		expected string
	}{
		{"docker.io", "docker.io/"},
		{"quay.io/", "quay.io/"},
		{"gcr.io/some-repo", "gcr.io/some-repo/"},
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := addTrailingSlash(tc.input)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestIsPrereleaseEnterpriseVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "master",
			want:    false,
		},
		{
			version: "release-v3.25",
			want:    false,
		},
		{
			version: "release-calient-v3.25",
			want:    false,
		},
		{
			version: "v3.25.0",
			want:    true,
		},
		{
			version: "v3.25.0-rc1",
			want:    false,
		},
		{
			version: "v3.25.0-1.0",
			want:    true,
		},
		{
			version: "v3.25.0-2.0",
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := isEnterpriseReleaseVersionFormat(tc.version)
			if err != nil {
				t.Fatalf("isEnterpriseReleaseVersionFormat(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isEnterpriseReleaseVersionFormat(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}
