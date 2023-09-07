package util

import (
	"strings"

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
			name = q.Name[:len(q.Name)-len(zone)-1]
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

	// check if the requested name is in the database at all, otherwise return NXDOMAIN
	// This is designed to assume that it is more efficient to query the database twice,
	// once for "the first record for this name" and once for "all records for this name
	// and type," as opposed to querying the database once for "all records for this name"
	// and then filtering out the ones that don't match the type.
	// The reasoning behind this is because it's almost certainly faster for the database to
	// look at the index twice than it is for us to iterate over an entire slice of all records
	// for a name.
	result := h.DB.Where("LOWER(name) = LOWER(?) AND LOWER(zone) = LOWER (?)", name, req.Question[0].Name[len(name)+1:]).Take(&pb.DNSRecord{})
	switch result.Error {
	case nil:
		// do nothing
	case gorm.ErrRecordNotFound:
		log.Errorf("Requested name %s (%v) not found in database",
			name, q.Name)
		m.SetRcode(req, dns.RcodeNameError)
		err := resp.WriteMsg(m)
		if err != nil {
			log.Errorf("Error writing response: %s", err)
		}
		return
	default:
		log.Errorf("Error querying database: %s", result.Error)
		m.SetRcode(req, dns.RcodeServerFailure)
		err := resp.WriteMsg(m)
		if err != nil {
			log.Errorf("Error writing response: %s", err)
		}
		return
	}

	// switch based on the type of query
	switch q.Qtype {
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
		m.Answer = append(m.Answer, h.autoRRFormatter(records)...)

		// add the SOA record to the end of the response, as per RFC 5936
		m.Answer = append(m.Answer, h.genSOA(resp, req, name))
		log.Tracef("%#v", m.Answer)
		m.SetRcode(req, dns.RcodeSuccess)
		err := resp.WriteMsg(m)
		if err != nil {
			log.Errorf("Error writing response: %s", err)
		}

	default:
		var records []*pb.DNSRecord
		h.DB.Where("LOWER(name) = LOWER(?) AND type = ?", name, q.Qtype).Find(&records)
		if _, ok := recordToFmt[q.Qtype]; !ok {
			log.Errorf("Unsupported query type %d", q.Qtype)
			m.SetRcode(req, dns.RcodeNotImplemented)
			break
		}
		m.Answer = append(m.Answer, h.autoRRFormatter(records)...)
	}

	err := resp.WriteMsg(m)
	if err != nil {
		log.Errorf("Error writing response: %s", err)
		log.Tracef("%#v", m.Answer[0])
	}
}
