package prisma_session

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"

	CloudType "github.com/sshintaku/cloud_types"
	"github.com/sshintaku/web_requests"
)

type Session struct {
	Token   string
	BaseUrl string
}

func (s *Session) CreateSession() {
	username := os.Getenv("APIKEY")
	password := os.Getenv("PASSWORD")
	authResponse, _ := web_requests.GetJWTToken("https://api2.prismacloud.io/login", username, password)
	s.Token = authResponse.Token

	computeUrl, baseUrlError := web_requests.GetComputeBaseUrl(s.Token)
	s.BaseUrl = computeUrl
	if baseUrlError != nil {
		log.Fatal(baseUrlError)
	}
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func GetMaintainerList(listToProcess []CloudType.ComplianceObject) []string {
	var maintainerList []string
	for _, item := range listToProcess {
		for _, label := range item.Labels {
			match, _ := regexp.MatchString("^maintainer:", label)
			if match {
				if !Find(maintainerList, label) {
					maintainerList = append(maintainerList, label)
				}
			}
		}
	}
	nullMaintainer := ""
	maintainerList = append(maintainerList, nullMaintainer)
	return maintainerList
}

func (s *Session) GetSampleDeployedImages() []CloudType.ComplianceObject {
	var jsonObject []CloudType.ComplianceObject
	var complianceList []CloudType.ComplianceObject
	uri := s.BaseUrl + "/api/v1/images?limit=5"
	results, resultError := web_requests.GetMethod(uri, s.Token)
	if resultError != nil {
		log.Fatal(resultError)
	}
	json.Unmarshal(results, &jsonObject)

	complianceList = append(complianceList, jsonObject...)
	return complianceList
}

func (s *Session) GetSamepleContainers() []CloudType.ContainerInfo {

	var jsonObject []CloudType.ContainerInfo
	var complianceList []CloudType.ContainerInfo

	uri := s.BaseUrl + "/api/v1/containers?limit=10"
	results, resultError := web_requests.GetMethod(uri, s.Token)
	if resultError != nil {
		log.Fatal(resultError)
	}
	fmt.Println(string(results))
	json.Unmarshal(results, &jsonObject)
	complianceList = append(complianceList, jsonObject...)

	return complianceList
}

func (s *Session) GetAllContainers() []CloudType.ContainerInfo {
	flag := true
	offsetValue := 0
	var jsonObject []CloudType.ContainerInfo
	var complianceList []CloudType.ContainerInfo

	for flag {
		uri := s.BaseUrl + "/api/v1/containers?limit=50&offset=" + strconv.Itoa(offsetValue)
		results, resultError := web_requests.GetMethod(uri, s.Token)
		if resultError != nil {
			log.Fatal(resultError)
		}
		if string(results) == "null" {
			flag = false
		} else {
			json.Unmarshal(results, &jsonObject)
			offsetValue = offsetValue + 50
			fmt.Println(string(results))
			complianceList = append(complianceList, jsonObject...)
		}
	}
	return complianceList
}

func (s *Session) GetDeployedImages() []CloudType.ComplianceObject {
	flag := true
	offsetValue := 0
	var complianceList []CloudType.ComplianceObject

	for flag {
		uri := s.BaseUrl + "/api/v1/images?limit=50&offset=" + strconv.Itoa(offsetValue)
		results, resultError := web_requests.GetMethod(uri, s.Token)
		if resultError != nil {
			log.Fatal(resultError)
		}
		if string(results) == "null" {
			flag = false
		} else {
			var jsonObject []CloudType.ComplianceObject
			json.Unmarshal(results, &jsonObject)
			for _, data := range jsonObject {
				if data.RepoTags.Repo == "demand-impact-baseline-event-service-release-green" {
					fmt.Println("Found it.")
				}

			}
			offsetValue = offsetValue + 50
			complianceList = append(complianceList, jsonObject...)
		}
	}
	return complianceList

}

func (s *Session) GetImageCVEInfo(cve string) []CloudType.ImageInfo {
	uri := s.BaseUrl + "/api/v1/stats/vulnerabilities/impacted-resources?cve=" + cve
	results, resultError := web_requests.GetMethod(uri, s.Token)
	if resultError != nil {
		log.Fatal(resultError)
	}
	var list []CloudType.ImageInfo
	var jsonObject CloudType.ImageOutput
	json.Unmarshal(results, &jsonObject)
	for _, value := range jsonObject.RiskTree {
		output := value.([]interface{})

		for _, subValue := range output {
			var imageInfo CloudType.ImageInfo
			output2 := subValue.(map[string]interface{})
			for key, subsubValue := range output2 {
				output3 := fmt.Sprintf("%v", subsubValue)
				if key == "host" {
					imageInfo.Host = output3
				}
				if key == "image" {
					imageInfo.Image = output3
				}
				if key == "container" {
					imageInfo.Container = output3
				}
			}
			list = append(list, imageInfo)
		}

	}
	return list
}

