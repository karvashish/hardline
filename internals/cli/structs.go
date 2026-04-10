package cli

type Command struct {
	Name              string
	Profile           string
	Host              string
	Port              int
	User              string
	KeyPath           string
	OverridesFile     string
	LogFile           string
	ReportFile        string
	ReportFormat      string
	KeepLocalRollback bool
	ForceRollback     bool
	AllowLocalKey     bool
	Debug             bool
}
