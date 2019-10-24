package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.10.0"
	VersionCalicoCNI             = "v3.10.0"
	VersionCalicoTypha           = "v3.10.0"
	VersionCalicoKubeControllers = "v3.10.0"
	VersionFlexVolume            = "v3.10.0"
	VersionCPHAutoscaler         = "1.7.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.0-0.dev-170-gecea86e-dirty"
	VersionTigeraTypha           = "v2.6.0-0.dev-104-g6c51073"
	VersionTigeraKubeControllers = "v2.6.0-0.dev-86-g506e244-dirty"

	// API server images.
	VersionAPIServer   = "v2.5.0-mcm0.1-31-g54c4ff40"
	VersionQueryServer = "v2.6.0-0.dev-7-g5e69bfc"

	// Logging
	VersionFluentd = "v2.6.0-0.dev-27-gdd525f5"

	// Compliance images.
	VersionComplianceController  = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceReporter    = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceServer      = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceSnapshotter = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceBenchmarker = "v2.6.0-0.dev-42-g5bb7357"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.6.0-0.dev-53-g6045051"
	VersionIntrusionDetectionJobInstaller = "v2.6.0-0.dev-53-g6045051"

	// Manager images.
	VersionManager        = "v2.6.0-0.dev-1-g68a6585"
	VersionManagerProxy   = "v1.0.0.rc1"
	VersionManagerEsProxy = "v2.6.0-0.dev-88-gbd4f9c3"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "es7-v2.6.0-dev-9184ce66033a"

	VersionKibana = "7.3"
)
