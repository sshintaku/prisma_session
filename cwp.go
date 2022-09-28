package prisma_session

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	CloudType "github.com/sshintaku/cloud_types"
	"github.com/sshintaku/web_requests"
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

func (s *Session) GetAllIncidents() {
	flag := true
	offsetValue := 0
	var complianceList []CloudType.ComplianceObject

	for flag {
		uri := s.ComputeBaseUrl + "/api/v22.06/audits/incidents?limit=50&offset=" + strconv.Itoa(offsetValue)
		results, resultError := web_requests.GetMethod(uri, s.Token)
		if resultError != nil {
			log.Fatal(resultError)
		}
		if string(results) == "null" {
			flag = false
		} else {
			var jsonObject []CloudType.ComplianceObject
			json.Unmarshal(results, &jsonObject)
			offsetValue = offsetValue + 50
			complianceList = append(complianceList, jsonObject...)
		}
	}

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

func (s *Session) GetAllRegistryNames() []string {

	flag := true
	offsetValue := 0
	var list []string
	for flag {
		uri := s.ComputeBaseUrl + "/api/v22.06/registry/names?limit=50&offset=" + strconv.Itoa(offsetValue)
		results, resultError := web_requests.GetMethod(uri, s.Token)
		if resultError != nil {
			log.Fatal(resultError)
		}
		if string(results) == "null" {
			flag = false
		} else {
			var jsonObject []string
			json.Unmarshal(results, &jsonObject)
			offsetValue = offsetValue + 50
			list = append(list, jsonObject...)
		}
	}
	return list
}

func (s *Session) GetOneRegistryName() []string {

	offsetValue := 0
	var list []string

	uri := s.ComputeBaseUrl + "/api/v22.06/registry/names?limit=1&offset=" + strconv.Itoa(offsetValue)
	results, resultError := web_requests.GetMethod(uri, s.Token)
	if resultError != nil {
		log.Fatal(resultError)
	}

	var jsonObject []string
	json.Unmarshal(results, &jsonObject)
	offsetValue = offsetValue + 50
	list = append(list, jsonObject...)

	return list
}
