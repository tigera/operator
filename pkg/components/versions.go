package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.8.1"
	VersionCalicoCNI             = "v3.8.1"
	VersionCalicoTypha           = "v3.8.1"
	VersionCalicoKubeControllers = "v3.8.1"
	VersionFlexVolume            = "v3.8.1"
	VersionCPHAutoscaler         = "1.7.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.5.0"
	VersionTigeraTypha           = "v2.4.2"
	VersionTigeraKubeControllers = "v2.4.2"

	// API server images.
	VersionAPIServer   = "v2.5.0"
	VersionQueryServer = "v2.4.0"

	// Logging
	VersionFluentd = "es7-v2.5.1-dev-1"

	// Compliance images.
	VersionComplianceController  = "es7-v2.5.1-dev-1"
	VersionComplianceReporter    = "es7-v2.5.1-dev-1"
	VersionComplianceServer      = "es7-v2.5.1-dev-1"
	VersionComplianceSnapshotter = "es7-v2.5.1-dev-1"
	VersionComplianceBenchmarker = "es7-v2.5.1-dev-1"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "es7-v2.5.1-dev-1"
	VersionIntrusionDetectionJobInstaller = "es7-v2.5.1-dev-1"

	// Manager images.
	VersionManager        = "v2.4.2"
	VersionManagerProxy   = "v1.0.0.rc1"
	VersionManagerEsProxy = "v2.4.0"

	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.0"
)
