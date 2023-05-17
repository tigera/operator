// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package logstorage

const (
	// Secret and volume name used for client certificate and key. Used by Linseed and es-gateway
	// when mTLS to external Elasticsearch is enabled. The secret contains the client certificate
	// and key to present to elastic.
	ExternalCertsSecret     = "tigera-secure-external-es-certs"
	ExternalCertsVolumeName = "tigera-secure-external-es-certs"
)
