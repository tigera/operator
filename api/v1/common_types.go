// Copyright (c) 2022, 2023 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

// Metadata contains the standard Kubernetes labels and annotations fields.
type Metadata struct {
	// Labels is a map of string keys and values that may match replicaset and
	// service selectors. Each of these key/value pairs are added to the
	// object's labels provided the key does not already exist in the object's labels.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations is a map of arbitrary non-identifying metadata. Each of these
	// key/value pairs are added to the object's annotations provided the key does not
	// already exist in the object's annotations.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type LogLevel string

const (
	LogLevelTrace LogLevel = "Trace"
	LogLevelInfo  LogLevel = "Info"
	LogLevelDebug LogLevel = "Debug"
	LogLevelWarn  LogLevel = "Warn"
	LogLevelFatal LogLevel = "Fatal"
	LogLevelError LogLevel = "Error"
)
