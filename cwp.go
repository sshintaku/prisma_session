package prisma_session

import (
	"fmt"
	"strconv"
	"time"

	CloudType "github.com/sshintaku/cloud_types"
)

func (s *Session) GetCollectionList(data []CloudType.ComplianceObject) []string {
	var list []string
	for _, item := range data {
		for _, collectionName := range item.Collections {
			result := inList(list, collectionName)
			if !result {
				list = append(list, collectionName)
			}
		}
	}
	return list

}

func inList(list []string, collectionName string) bool {
	for _, item := range list {
		if collectionName == item {
			return true
		}
	}
	return false
}

func GetDataByCollection(collectionnames []string, data []CloudType.ComplianceObject) {
	report := "Collection Name, Time Stamp, No. of Critical, No. of High, No. of Important, No. of Medium, No. of Low"
	fmt.Println(report)
	for _, collectionName := range collectionnames {
		var list []CloudType.ComplianceObject
		for _, item := range data {
			result := isInCollection(collectionName, item.Collections)
			if result {
				list = append(list, item)
			}
		}
		var critical, high, important, medium, low int
		for _, item := range list {

			for _, vulnerability := range item.VulnerabilityIssues {
				switch vulnerability.Severity {
				case "critical":
					critical++
				case "high":
					high++
				case "important":
					important++
				case "medium":
					medium++
				case "low":
					low++
				}
			}

		}
		if list != nil {
			fmt.Printf("%s,%s,%s, %s,%s, %s, %s\n", collectionName, time.Now(), strconv.Itoa(critical), strconv.Itoa(high), strconv.Itoa(important), strconv.Itoa(medium), strconv.Itoa(low))
		} else {
			fmt.Printf("%s,%s", collectionName, "N/A\n")
		}
	}

	//fmt.Println("For collection: " + collectionname)
}

func isInCollection(collectionName string, collectionArray []string) bool {
	for _, item := range collectionArray {
		if item == collectionName {
			return true
		}
	}
	return false
}
