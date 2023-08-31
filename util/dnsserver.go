package util

import (
	"net"
	"strings"
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
		m.Answer = append(m.Answer, h.genSOA(resp, req, name))
	case dns.TypeAXFR:
		// check if the requester is in the axfr allowed list
		var allowed bool
		for _, addr := range h.Config.DnsConf.GetAxfrTo() {
			if strings.HasPrefix(resp.RemoteAddr().String(), addr) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Errorf("AXFR request from %s denied", resp.RemoteAddr().String())
			m.SetRcode(req, dns.RcodeRefused)
			err := resp.WriteMsg(m)
			if err != nil {
				log.Errorf("Error writing response: %s", err)
			}
			return
		}

		m.MsgHdr.Zero = false
		m.MsgHdr.AuthenticatedData = false
		m.MsgHdr.CheckingDisabled = false
		m.MsgHdr.RecursionDesired = req.MsgHdr.RecursionDesired
		m.MsgHdr.RecursionAvailable = false

		// generate the SOA record and prepend it to the response
		m.Answer = []dns.RR{h.genSOA(resp, req, name)}

		// get all non-SOA records for the requested name
		var records []*pb.DNSRecord
		h.DB.Where("LOWER(name) = LOWER(?) AND type != ?", name, dns.TypeSOA).Find(&records)
		for _, record := range records {
			switch record.Type {
			// ignore SOA records
			case uint32(dns.TypeSOA):
			case uint32(dns.TypeAAAA):
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{
					Name:   processFullName(record),
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    record.GetTtl(),
				}
				rr.AAAA = net.ParseIP(record.GetValue())
				m.Answer = append(m.Answer, rr)
			}
		}
		// add the SOA record to the end of the response, as per RFC 5936
		m.Answer = append(m.Answer, h.genSOA(resp, req, name))
		log.Tracef("%#v", m.Answer)
		m.SetRcode(req, dns.RcodeSuccess)
		err := resp.WriteMsg(m)
		if err != nil {
			log.Errorf("Error writing response: %s", err)
		}

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

func (h DNSHandler) genSOA(resp dns.ResponseWriter, req *dns.Msg,
	name string) dns.RR {
	// check the db for the SOA record
	var pbrr pb.DNSRecord
	h.DB.Where("LOWER(name) = LOWER(?) AND type = ?", name, dns.TypeSOA).First(&pbrr)

	// temporarily make the SOA record manually
	q := req.Question[0]
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
	return rr
}
