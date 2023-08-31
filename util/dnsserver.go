package util

import (
	"time"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
	"github.com/gidoBOSSftw5731/log"
	"github.com/miekg/dns"
	"gorm.io/gorm"
)

type DNSHandler struct {
	Config *pb.ServerConfig
	DB     *gorm.DB
}

func (h DNSHandler) HandleDNS(resp dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = false

	q := req.Question[0]
	log.Tracef("%#v", q)

	// Check that the name being requested is part of a zone we manage
	var name string
	for _, zone := range h.Config.GetDnsConf().GetRootZones() {
		if dns.IsSubDomain(zone, q.Name) {
			log.Traceln("Found zone", zone, "for name", q.Name)
			name = q.Name[:len(q.Name)-len(zone)]
			if name == "" {
				name = "@"
			}
			break
		}
	}

	log.Traceln("Name:", name)

	if name == "" {
		log.Errorf("Requested name %s (%v) is not part of a zone we manage",
			name, q.Name)
		m.SetRcode(req, dns.RcodeNameError)
		err := resp.WriteMsg(m)
		if err != nil {
			log.Errorf("Error writing response: %s", err)
		}
		return
	}

	switch q.Qtype {
	case dns.TypeAAAA:

	case dns.TypeSOA:
		// check the db for the SOA record
		var pbrr pb.DNSRecord
		h.DB.Where("LOWER(name) = LOWER(?) AND type = ?", name, dns.TypeSOA).First(&pbrr)

		// Set the SOA record
		rr := new(dns.SOA)
		rr.Hdr = dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		}
		log.Tracef("RR Hdr: %#v", rr.Hdr)
		rr.Ns = h.Config.DnsConf.GetNsAddr()
		rr.Mbox = h.Config.DnsConf.GetAdminEmail()
		rr.Serial = uint32(time.Now().Unix())
		m.Answer = append(m.Answer, rr)
	case dns.TypeAXFR:
		// TODO: deal with axfr requests
	default:
		log.Errorf("Unsupported query type %d", q.Qtype)
		m.SetRcode(req, dns.RcodeNotImplemented)
	}

	err := resp.WriteMsg(m)
	if err != nil {
		log.Errorf("Error writing response: %s", err)
		log.Tracef("%#v", m.Answer[0])
	}
}
