package prisma_session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"syscall"

	CloudType "github.com/sshintaku/cloud_types"
	"github.com/sshintaku/web_requests"
)

type Session struct {
	Token          string
	ComputeBaseUrl string
	ImageData      *[]CloudType.ComplianceObject
	ApiUrl         string
}

func (s *Session) CreateSession() {
	username := os.Getenv("APIKEY")
	if username == "" {
		log.Fatalln("APIKEY environment variable is not set.")
	}
	password := os.Getenv("PASSWORD")
	if password == "" {
		log.Fatalln("PASSWORD environment variable is not set.")
	}
	url := s.ApiUrl + "login"
	authResponse, authError := web_requests.GetJWTToken(url, username, password)
	if authError != nil {
		fmt.Println("Error with authorization session creation.")
		log.Fatal(authError)
	}
	s.Token = authResponse.Token

	computeUrl, baseUrlError := web_requests.GetComputeBaseUrl(s.Token)
	s.ComputeBaseUrl = computeUrl
	if baseUrlError != nil {
		log.Fatal(baseUrlError)
	}
}

func (s *Session) GetCompliancePosture(filter CloudType.CSPMFilter) {
	url := s.ApiUrl + "compliance/posture"
	json, error := json.Marshal(filter)
	if error != nil {
		log.Fatal(error)
	}
	result, resultError := web_requests.PostMethod(url, json, s.Token)
	if resultError == nil {
		log.Fatal(resultError)
	}
	fmt.Println(string(*result))
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func (s *Session) GetMaintainerList(regExpression string, listToProcess []CloudType.ComplianceObject) []string {
	var maintainerList []string
	for _, item := range listToProcess {
		for _, label := range item.Labels {
			match, _ := regexp.MatchString(regExpression, label)
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
	uri := s.ComputeBaseUrl + "/api/v1/images?limit=5"
	results, resultError := web_requests.GetMethod(uri, s.Token)
	if resultError != nil {
		log.Fatal(resultError)
	}
	json.Unmarshal(results, &jsonObject)

	complianceList = append(complianceList, jsonObject...)
	return complianceList
}

func (s *Session) GetSampleContainers() []CloudType.ContainerInfo {

	var jsonObject []CloudType.ContainerInfo
	var complianceList []CloudType.ContainerInfo

	uri := s.ComputeBaseUrl + "/api/v1/containers?limit=10"
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
		uri := s.ComputeBaseUrl + "/api/v1/containers?limit=50&offset=" + strconv.Itoa(offsetValue)
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
		uri := s.ComputeBaseUrl + "/api/v1/images?limit=50&offset=" + strconv.Itoa(offsetValue)
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

	return complianceList
}

func (s *Session) GetRegistry(offset int, maxRecords int) []CloudType.RegistryScan {
	var list []CloudType.RegistryScan
	flag := true
	offsetValue := offset

	for flag {
		uri := s.ComputeBaseUrl + "/api/v1/registry?limit=50&offset=" + strconv.Itoa(offsetValue)
		//fmt.Println(strconv.Itoa(offsetValue))
		//time.Sleep(1 * time.Second)
		results, resultError := web_requests.GetMethod(uri, s.Token)

		if errors.Is(resultError, syscall.ECONNRESET) {
			retryResult, retryError := web_requests.GetMethod(uri, s.Token)
			if retryError != nil {
				log.Fatal(resultError)
			}
			results = retryResult

		}
		if string(results) == "null" || offsetValue >= maxRecords {
			flag = false
		} else {
			var jsonObject []CloudType.RegistryScan
			json.Unmarshal(results, &jsonObject)
			offsetValue = offsetValue + 50
			//fmt.Println(string(results))
			list = append(list, jsonObject...)
		}

	}
	return list
}

func (s *Session) GetCSPMAlerts(payload CloudType.AlertQuery) ([]CloudType.AlertModel, error) {
	uri := s.ApiUrl + "v2/alert"
	request, requestError := http.NewRequest("GET", uri, nil)
	if requestError != nil {
		log.Fatalln(requestError)
	}
	q := request.URL.Query()
	q.Add("timeType", payload.TimeType)
	q.Add("timeAmount", payload.TimeAmount)
	q.Add("detailed", strconv.FormatBool(payload.Detailed))
	q.Add("timeUnit", payload.TimeUnit)
	q.Add("limit", "50")
	q.Add("policy.severity", payload.Severity)
	q.Add("policy.name", payload.PolicyName)
	q.Add("alert.status", payload.AlertStatus)
	switch {
	case payload.ServiceName != nil:
		q.Add("cloud.service", *payload.ServiceName)
	}
	request.Header.Add("x-redlock-auth", s.Token)
	request.URL.RawQuery = q.Encode()
	var result []CloudType.AlertModel

	flag := true
	for flag {
		retryResult, retryError := web_requests.ProcessWebRequest(request)
		if retryError != nil {
			log.Fatalln(retryError)

		}

		var alert CloudType.AlertResponse
		unmarshallError := json.Unmarshal(retryResult, &alert)
		if alert.NextPageToken == "" || alert.NextPageToken == "null" {
			flag = false
		} else {
			for _, item := range alert.AlertModelArray {
				result = append(result, item)
			}
			if unmarshallError != nil {
				log.Fatalln(unmarshallError)
				return nil, unmarshallError
			}
			request.Header.Set("pageToken", alert.NextPageToken)
		}
	}
	return result, nil
}
func (s *Session) GetRuntimeAudits(excludeAlarms []string) []CloudType.AuditType {
	var list []CloudType.AuditType
	flag := true
	offsetValue := 0
	for flag {
		uri := s.ComputeBaseUrl + "/api/v1/audits/incidents?limit=50&offset=" + strconv.Itoa(offsetValue)
		results, resultError := web_requests.GetMethod(uri, s.Token)
		if resultError != nil {
			log.Fatal(resultError)
		}
		if string(results) == "null" || string(results) == "" {
			flag = false
		} else {
			var jsonObject []CloudType.AuditType
			json.Unmarshal(results, &jsonObject)
			offsetValue = offsetValue + 50
			list = append(list, jsonObject...)
		}

	}
	return list
}

func (s *Session) GetImageCVEInfo(cve string) []CloudType.ImageInfo {
	uri := s.ComputeBaseUrl + "/api/v1/stats/vulnerabilities/impacted-resources?cve=" + cve
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

func (s *Session) GetMaintainerImages(regExString string, imageData []CloudType.ComplianceObject) []CloudType.ComplianceObject {
	var list []CloudType.ComplianceObject
	for _, data := range imageData {
		for _, label := range data.Labels {

			match, _ := regexp.MatchString(regExString, label)
			if match {
				list = append(list, data)
			}
		}
	}
	return list
}
