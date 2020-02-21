package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.10.1"
	VersionCalicoCNI             = "v3.10.1"
	VersionCalicoTypha           = "v3.10.1"
	VersionCalicoKubeControllers = "v3.10.1"
	VersionFlexVolume            = "v3.10.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "release-v2.6"
	VersionTigeraTypha           = "release-v2.6"
	VersionTigeraKubeControllers = "release-v2.6"

	// API server images.
	VersionAPIServer   = "release-v2.6"
	VersionQueryServer = "release-v2.6"

	// Logging
	VersionFluentd = "release-v2.6"

	// Compliance images.
	VersionComplianceController  = "release-v2.6"
	VersionComplianceReporter    = "release-v2.6"
	VersionComplianceServer      = "release-v2.6"
	VersionComplianceSnapshotter = "release-v2.6"
	VersionComplianceBenchmarker = "release-v2.6"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "release-v2.6"
	VersionIntrusionDetectionJobInstaller = "release-v2.6"

	// Manager images.
	VersionManager        = "release-v2.6"
	VersionManagerProxy   = "release-v2.6"
	VersionManagerEsProxy = "release-v2.6"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "release-v2.6"

	VersionKibana = "release-v2.6"
)
