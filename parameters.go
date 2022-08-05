package prisma_session

import (
	"encoding/json"
	"log"
	"os"

	CloudType "github.com/sshintaku/cloud_types"
)

type Parameters struct {
	AlarmLevels          []string
	RegEx                string
	FixDate              int
	ApiUrl               string
	IgnoreAudits         []string
	AlertQueryParameters CloudType.AlertQuery
}

func ReadParameters() Parameters {
	var params Parameters
	paramBytes, err := os.ReadFile(".parameter.json")
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(paramBytes, &params)
	if len(params.AlarmLevels) == 0 {
		log.Fatalln("The alarm levels must not be empty.  There should be at least one value such as \"critical\"")
	}
	return params
}
