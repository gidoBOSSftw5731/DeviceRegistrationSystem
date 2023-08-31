package util

import (
	"net"
	"time"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
	"github.com/miekg/dns"
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

func fmtAAAA(record *pb.DNSRecord) *dns.AAAA {
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

func (h DNSHandler) fmtA(record *pb.DNSRecord) *dns.A {
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
