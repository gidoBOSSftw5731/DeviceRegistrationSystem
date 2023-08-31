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
		"ttl": &dnsRecord.Ttl,
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
	// enums
	i, err := strconv.Atoi(req.FormValue("ttl"))
	if err != nil {
		return nil, err
	}
	dnsRecord.Ttl = uint32(i)
	if dnsRecord.Ttl == 0 {
		return nil, fmt.Errorf("missing field %s", "ttl")
	}

	return dnsRecord, nil
}
