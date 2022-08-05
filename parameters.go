package prisma_session

type Parameters struct {
	AlarmLevels          []string
	RegEx                string
	FixDate              int
	ApiUrl               string
	IgnoreAudits         []string
	AlertQueryParameters CloudType.AlertQuery
}
