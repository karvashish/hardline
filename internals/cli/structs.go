package cli

type Command struct {
	Name              string
	Profile           string
	Host              string
	User              string
	KeyPath           string
	LogFile           string
	ReportFile        string
	ReportFormat      string
	KeepLocalRollback bool
	Debug             bool
}
