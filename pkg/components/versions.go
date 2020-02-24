package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.10.3"
	VersionCalicoCNI             = "v3.10.3"
	VersionCalicoTypha           = "v3.10.3"
	VersionCalicoKubeControllers = "v3.10.3"
	VersionFlexVolume            = "v3.10.3"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.2"
	VersionTigeraTypha           = "v2.6.2"
	VersionTigeraKubeControllers = "v2.6.2"

	// API server images.
	VersionAPIServer   = "v2.6.2"
	VersionQueryServer = "v2.6.2"

	// Logging
	VersionFluentd = "v2.6.2"

	// Compliance images.
	VersionComplianceController  = "v2.6.2"
	VersionComplianceReporter    = "v2.6.2"
	VersionComplianceServer      = "v2.6.2"
	VersionComplianceSnapshotter = "v2.6.2"
	VersionComplianceBenchmarker = "v2.6.2"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.6.2"
	VersionIntrusionDetectionJobInstaller = "v2.6.2"

	// Manager images.
	VersionManager        = "v2.6.2"
	VersionManagerProxy   = "v2.6.2"
	VersionManagerEsProxy = "v2.6.2"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.2"

	VersionKibana = "v2.6.2"
)
