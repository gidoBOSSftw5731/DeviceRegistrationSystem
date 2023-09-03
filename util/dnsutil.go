package util

import (
	"fmt"
	"net/http"
	"strconv"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
	"github.com/gidoBOSSftw5731/log"
	"github.com/miekg/dns"
)

var (
	f *interface{}
	// these settings are for types of records which require certain fields.
	requireValue = map[uint16]*interface{}{
		dns.TypeAAAA:  f,
		dns.TypeA:     f,
		dns.TypeCNAME: f,
		dns.TypeNS:    f,
		dns.TypePTR:   f,
		dns.TypeTXT:   f,
		dns.TypeMX:    f}
	requirePriority = map[uint16]*interface{}{
		dns.TypeMX: f}
	requireTrailingPeriodInValue = map[uint16]*interface{}{
		dns.TypeCNAME: f,
		dns.TypeNS:    f,
		dns.TypePTR:   f,
		dns.TypeMX:    f}
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
	// all of these are mandatory
	for field, val := range map[string]*string{
		"user": &dnsRecord.User,
		"name": &dnsRecord.Name,
		"zone": &dnsRecord.Zone,
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

	// set the optional fields based on the type
	requiredFields := map[string]*string{}

	if _, ok := requireValue[uint16(dnsRecord.GetType())]; ok {
		requiredFields["value"] = &dnsRecord.Value
	}
	if _, ok := requirePriority[uint16(dnsRecord.GetType())]; ok {
		requiredFields["priority"] = &dnsRecord.Priority
	}

	for field, val := range requiredFields {
		*val = req.FormValue(field)
		if *val == "" {
			return nil, fmt.Errorf("missing field %s", field)
		}
	}

	if _, ok := requireTrailingPeriodInValue[uint16(dnsRecord.GetType())]; ok {
		if dnsRecord.GetValue()[len(dnsRecord.GetValue())-1] != '.' {
			return nil, fmt.Errorf("value field must end with a period")
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

// autoRRFormatter calls singleAutoRRFormatter for each record in records,
// and returns a slice of the results.
func (h DNSHandler) autoRRFormatter(records []*pb.DNSRecord) []dns.RR {
	var ret []dns.RR
	// This one loop works for the *vast majority* of records,
	// where all the handlers are somewhere else.
	for _, record := range records {
		ret = append(ret, h.singleAutoRRFormatter(record))
	}
	return ret
}

func (h DNSHandler) singleAutoRRFormatter(record *pb.DNSRecord) dns.RR {
	if formatter, ok := recordToFmt[uint16(record.Type)]; ok {
		log.Tracef("Formatting record %#v", record)
		return formatter(record)
	}
	return nil
}
