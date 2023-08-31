package util

import (
	"fmt"
	"net/http"
	"strconv"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
)

func ParseDNSRecord(req *http.Request) (*pb.DNSRecord, error) {
	dnsRecord := &pb.DNSRecord{}

	// parse the POST form
	err := req.ParseForm()
	if err != nil {
		return nil, err
	}

	// set the fields of the DNSRecord using a map of the fields and pointers to their locations
	// in the struct
	for field, val := range map[string]*string{
		"user":  &dnsRecord.User,
		"name":  &dnsRecord.Name,
		"value": &dnsRecord.Value,
		"zone":  &dnsRecord.Zone,
	} {
		*val = req.FormValue(field)
		if *val == "" {
			return nil, fmt.Errorf("missing field %s", field)
		}
	}

	// do the same as above for non-string fields
	for field, val := range map[string]*uint32{
		"ttl":  &dnsRecord.Ttl,
		"type": &dnsRecord.Type,
	} {
		i, err := strconv.Atoi(req.FormValue(field))
		if err != nil {
			return nil, err
		}
		*val = uint32(i)
		if *val == 0 {
			return nil, fmt.Errorf("missing field %s", field)
		}
	}

	return dnsRecord, nil
}

func processFullName(record *pb.DNSRecord) string {
	switch record.GetName() {
	case "@":
		return record.GetZone()
	default:
		return fmt.Sprintf("%s.%s", record.GetName(), record.GetZone())
	}
}
