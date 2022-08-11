package prisma_session

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	CloudType "github.com/sshintaku/cloud_types"
)

func GenerateAlertSummary(data []CloudType.AlertModel) {
	var total int
	for _, item := range data {
		switch {
		case item.Resource.CloudServiceName == "Amazon EC2":
			fmt.Println("*******************")
			fmt.Println("Public DNS Name, Public IP Address, Private DNS Name, Private IP Address, Security Groups, VPC Id, Account Group, Cloud Account Name, Resource Name")
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
			report += ", " + ec2.VpcId
			fmt.Println(report)
			fmt.Println("*******************")
			total = total + 1
		default:
		}
	}
	fmt.Println("Total number of alerts: " + strconv.Itoa(total))
}
