package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.8.1"
	VersionCalicoCNI             = "v3.8.1"
	VersionCalicoTypha           = "v3.8.1"
	VersionCalicoKubeControllers = "v3.8.1"
	VersionFlexVolume            = "v3.8.1"
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

	// Compliance images.
	VersionComplianceController  = "v2.4.2"
	VersionComplianceReporter    = "v2.4.2"
	VersionComplianceServer      = "v2.4.2"
	VersionComplianceSnapshotter = "v2.4.2"
	VersionComplianceBenchmarker = "v2.5.0"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.4.2"
	VersionIntrusionDetectionJobInstaller = "v2.4.2"

	// Console images.
	VersionConsoleManager = "v2.4.2"
	VersionConsoleProxy   = "v2.4.2"
	VersionConsoleEsProxy = "v2.4.0"
)
