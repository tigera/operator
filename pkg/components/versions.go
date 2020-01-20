package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.11.1-with-auto-backend"
	VersionCalicoCNI             = "v3.11.1"
	VersionCalicoTypha           = "v3.11.1"
	VersionCalicoKubeControllers = "v3.11.1"
	VersionFlexVolume            = "v3.11.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "master"
	VersionTigeraTypha           = "master"
	VersionTigeraKubeControllers = "master"

	// API server images.
	VersionAPIServer   = "master"
	VersionQueryServer = "master"

	// Logging
	VersionFluentd = "master"

	// Compliance images.
	VersionComplianceController  = "master"
	VersionComplianceReporter    = "master"
	VersionComplianceServer      = "master"
	VersionComplianceSnapshotter = "master"
	VersionComplianceBenchmarker = "master"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "master"
	VersionIntrusionDetectionJobInstaller = "master"

	// Manager images.
	VersionManager        = "master"
	VersionManagerProxy   = "master"
	VersionManagerEsProxy = "master"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "master"

	VersionKibana = "7.3"

	// Multicluster tunnel image.
	VersionGuardian = "master"
)
