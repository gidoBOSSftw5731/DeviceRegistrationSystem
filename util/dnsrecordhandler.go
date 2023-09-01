package util

import (
	"net"
	"strconv"
	"time"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
	"github.com/gidoBOSSftw5731/log"
	"github.com/miekg/dns"
)

var (
	recordToFmt = map[uint16]func(*pb.DNSRecord) dns.RR{
		dns.TypeAAAA: fmtAAAA,
		dns.TypeA:    fmtA,
		dns.TypeMX:   fmtMX,
	}
)

func (h DNSHandler) genSOA(resp dns.ResponseWriter, req *dns.Msg,
	name string) dns.RR {
	// check the db for the SOA record
	var pbrr pb.DNSRecord
	h.DB.Where("LOWER(name) = LOWER(?) AND type = ?", name, dns.TypeSOA).First(&pbrr)

	// Set the SOA record
	rr := new(dns.SOA)
	rr.Hdr = dns.RR_Header{
		Name:   processFullName(&pbrr),
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		Ttl:    pbrr.GetTtl(),
	}
	//log.Tracef("RR Hdr: %#v", rr.Hdr)
	rr.Ns = h.Config.DnsConf.GetNsAddr()
	rr.Expire = 3600000
	rr.Refresh = 86400
	rr.Minttl = 300
	rr.Retry = 3600
	rr.Mbox = h.Config.DnsConf.GetAdminEmail()
	rr.Serial = uint32(time.Now().Unix())
	return rr
}

func fmtAAAA(record *pb.DNSRecord) dns.RR {
	rr := new(dns.AAAA)
	rr.Hdr = dns.RR_Header{
		Name:   processFullName(record),
		Rrtype: dns.TypeAAAA,
		Class:  dns.ClassINET,
		Ttl:    record.GetTtl(),
	}
	rr.AAAA = net.ParseIP(record.GetValue())
	return rr
}

func fmtA(record *pb.DNSRecord) dns.RR {
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{
		Name:   processFullName(record),
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    record.GetTtl(),
	}
	rr.A = net.ParseIP(record.GetValue())
	return rr
}

func fmtMX(record *pb.DNSRecord) dns.RR {
	rr := new(dns.MX)
	rr.Hdr = dns.RR_Header{
		Name:   processFullName(record),
		Rrtype: dns.TypeMX,
		Class:  dns.ClassINET,
		Ttl:    record.GetTtl(),
	}
	rr.Mx = record.GetValue()
	prio, err := strconv.ParseUint(record.GetPriority(), 10, 16)
	if err != nil {
		log.Errorln("Error parsing MX priority:", err)
	}
	rr.Preference = uint16(prio)
	return rr
}
