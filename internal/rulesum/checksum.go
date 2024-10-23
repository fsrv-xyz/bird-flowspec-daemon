package rulesum

import (
	"crypto/md5"
	"encoding/json"
	"sort"

	"github.com/google/nftables"
)

// CheckSum calculates an MD5 checksum of a slice of nftables.Rule pointers.
// It serializes each rule to JSON, sorts the serialized bytes to ensure consistency,
// computes individual MD5 sums for each rule, and then computes a final MD5 sum
// of the combined individual sums.
func CheckSum(rules []*nftables.Rule) [16]byte {
	// Slice to store individual MD5 sums
	var sums [][16]byte

	for _, rule := range rules {
		// Serialize the rule to JSON
		data, err := json.Marshal(rule)
		if err != nil {
			// Handle the error appropriately; here we skip the rule
			continue
		}

		// Sort the serialized bytes to ensure consistent ordering
		sortedData := make([]byte, len(data))
		copy(sortedData, data)
		sort.Slice(sortedData, func(i, j int) bool {
			return sortedData[i] < sortedData[j]
		})

		// Compute the MD5 sum of the sorted data
		sum := md5.Sum(sortedData)
		sums = append(sums, sum)
	}

	// Serialize the slice of sums to JSON
	finalData, err := json.Marshal(sums)
	if err != nil {
		// Handle the error appropriately; return zero value in this example
		return [16]byte{}
	}

	// Compute the final MD5 sum of the combined sums
	return md5.Sum(finalData)
}
