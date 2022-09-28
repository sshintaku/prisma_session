package prisma_session

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	CloudType "github.com/sshintaku/cloud_types"
	"github.com/sshintaku/web_requests"
)

func (s *Session) GenerateAlertSummary(data []CloudType.AlertModel, hostInfoDict map[string]string) {
	var total int
	fmt.Println("Public DNS Name, Public IP Address, Private DNS Name, Private IP Address, Security Groups, VPC Id, Account Group, Cloud Account Name, Resource Name")
	for _, item := range data {
		switch {
		case item.Resource.CloudServiceName == "Amazon EC2":
			ec2 := CloudType.EC2Data{}
			ec2Data, ec2DataError := json.Marshal(item.Resource.Data)

			if ec2DataError != nil {
				log.Println(ec2DataError)
			}
			json.Unmarshal([]byte(ec2Data), &ec2)
			report := ec2.PublicDnsName + "," + ec2.PublicIPAddress + "," + ec2.PrivateDnsName + "," + ec2.PrivateIPAddress + ","
			for _, group := range ec2.SecuirtyGroups {
				report += "Group ID: " + group.GroupId + " Group Name: " + group.GroupName + ";"

			}
			report += ", " + ec2.VpcId + "," + ec2.InstanceId + "," + hostInfoDict[ec2.InstanceId]
			fmt.Println(report)
			total = total + 1
		default:
		}
	}
	fmt.Println("Total number of alerts: " + strconv.Itoa(total))
}

func (s *Session) GetHostInfo(rrn CloudType.RRN) {
	uri := s.ApiUrl + "resource"
	rrninfo, rrnError := json.Marshal(rrn)
	if rrnError != nil {
		log.Fatal(rrnError)
	}
	result, retryError := web_requests.PostWebRequest(uri, rrninfo, &s.Token)
	if retryError != nil {
		log.Fatalln(retryError)

	}
	fmt.Println(string(*result))
}

func (s *Session) DescribeEC2Instances(parameters Parameters) map[string]string {
	uri := s.ApiUrl + "search/config"
	query := "config from cloud.resource where api.name = 'aws-ec2-describe-instances' AND json.rule = tags[*] contains eks"
	var queryParameters CloudType.Investigate
	queryParameters.Query = query
	queryParameters.TimeRange.Type = "relative"
	queryParameters.TimeRange.Value.Unit = "day"
	queryParameters.TimeRange.Value.Amount = 7
	jsonPayload, marshalError := json.Marshal(queryParameters)
	if marshalError != nil {
		log.Fatal(marshalError)
	}
	response, responseError := web_requests.PostMethod(uri, jsonPayload, s.Token)
	if responseError != nil {
		log.Fatalln(responseError)
	}
	var rqlResult CloudType.RQLType
	dict := make(map[string]string)
	responseBytes := []byte(*response)
	json.Unmarshal(responseBytes, &rqlResult)
	for _, rql := range rqlResult.Data.Items {

		ec2 := CloudType.EC2Data{}
		ec2Data, ec2DataError := json.Marshal(rql.Data)
		if ec2DataError != nil {
			log.Fatalln(ec2DataError)
		}
		json.Unmarshal(ec2Data, &ec2)

		for _, tag := range ec2.Tags {
			if strings.Contains(tag.Key, "kubernetes.io") {
				dict[ec2.InstanceId] = tag.Key
			}
		}
	}
	return dict
}
