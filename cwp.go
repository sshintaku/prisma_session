package prisma_session

import (
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
