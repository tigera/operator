package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.10.0"
	VersionCalicoCNI             = "v3.10.0"
	VersionCalicoTypha           = "v3.10.0"
	VersionCalicoKubeControllers = "v3.10.0"
	VersionFlexVolume            = "v3.10.0"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.0"
	VersionTigeraTypha           = "v2.6.0"
	VersionTigeraKubeControllers = "v2.6.0"

	// API server images.
	VersionAPIServer   = "v2.6.0"
	VersionQueryServer = "v2.6.0"

	// Logging
	VersionFluentd = "v2.6.0"

	// Compliance images.
	VersionComplianceController  = "v2.6.0"
	VersionComplianceReporter    = "v2.6.0"
	VersionComplianceServer      = "v2.6.0"
	VersionComplianceSnapshotter = "v2.6.0"
	VersionComplianceBenchmarker = "v2.6.0"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.6.0"
	VersionIntrusionDetectionJobInstaller = "v2.6.0"

	// Manager images.
	VersionManager        = "v2.6.0"
	VersionManagerProxy   = "v2.6.0"
	VersionManagerEsProxy = "v2.6.0"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.0"

	VersionKibana = "v2.6.0"
)
