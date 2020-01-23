package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.11.0-0.dev-131-gf96a2f0-amd64"
	VersionCalicoCNI             = "v3.11.1-20-gecab527"
	VersionCalicoTypha           = "v3.11.1-18-gdb9625b"
	VersionCalicoKubeControllers = "v3.11.1-19-gb2e70aa"
	VersionFlexVolume            = "v3.11.2-3-ga0e1c46"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.1"
	VersionTigeraTypha           = "v2.6.1"
	VersionTigeraKubeControllers = "v2.6.1"

	// API server images.
	VersionAPIServer   = "v2.6.1"
	VersionQueryServer = "v2.6.1"

	// Logging
	VersionFluentd = "v2.6.1"

	// Compliance images.
	VersionComplianceController  = "v2.6.1"
	VersionComplianceReporter    = "v2.6.1"
	VersionComplianceServer      = "v2.6.1"
	VersionComplianceSnapshotter = "v2.6.1"
	VersionComplianceBenchmarker = "v2.6.1"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.6.1"
	VersionIntrusionDetectionJobInstaller = "v2.6.1"

	// Manager images.
	VersionManager        = "v2.6.1"
	VersionManagerProxy   = "v2.6.1"
	VersionManagerEsProxy = "v2.6.1"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.1"

	VersionKibana = "v2.6.1"
)
