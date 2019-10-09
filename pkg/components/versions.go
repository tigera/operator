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
	VersionTigeraTypha           = "master"
	VersionTigeraKubeControllers = "v2.4.2"

	// API server images.
	VersionAPIServer   = "master"
	VersionQueryServer = "master"

	// Logging
	VersionFluentd = "es7-v2.5.1-dev-1"

	// Compliance images.
	VersionComplianceController  = "master"
	VersionComplianceReporter    = "v2.4.2"
	VersionComplianceServer      = "master"
	VersionComplianceSnapshotter = "master"
	VersionComplianceBenchmarker = "v2.5.1"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "master"
	VersionIntrusionDetectionJobInstaller = "master"

	// Console images.
	VersionConsoleManager = "master"
	VersionConsoleProxy   = "master"
	VersionConsoleEsProxy = "master"

	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.0"
)
