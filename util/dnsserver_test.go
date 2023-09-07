package util

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/DATA-DOG/go-txdb"
	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	HandleDNSTests = map[*dns.Question]*dns.Msg{
		{
			Name:   "test.invalid.zone.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}: {MsgHdr: dns.MsgHdr{Response: true, Opcode: 0,
			Authoritative: true, Truncated: false, RecursionDesired: true,
			RecursionAvailable: false, Zero: false, AuthenticatedData: false,
			CheckingDisabled: false, Rcode: dns.RcodeNameError},
			Question: []dns.Question{{Name: "test.invalid.zone.",
				Qtype: 0x1, Qclass: 0x1}},
			Answer: []dns.RR(nil), Ns: []dns.RR(nil), Extra: []dns.RR(nil),
		}, {
			Name:   "test.valid.zone.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}: {MsgHdr: dns.MsgHdr{Response: true, Opcode: 0,
			Authoritative: true, Truncated: false, RecursionDesired: true,
			RecursionAvailable: false, Zero: false, AuthenticatedData: false,
			CheckingDisabled: false, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "test.valid.zone.",
				Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "test.valid.zone.", Ttl: 50, Class: dns.ClassINET,
				Rrtype: dns.TypeA, Rdlength: 4},
				A: net.IP{1, 2, 3, 4}}},
		},
		{
			Name:   "test.valid.zone.",
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}: {MsgHdr: dns.MsgHdr{Response: true, Opcode: 0,
			Authoritative: true, Truncated: false, RecursionDesired: true,
			RecursionAvailable: false, Zero: false, AuthenticatedData: false,
			CheckingDisabled: false, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "test.valid.zone.",
				Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "test.valid.zone.",
				Ttl: 90, Class: dns.ClassINET, Rrtype: dns.TypeAAAA, Rdlength: 16},
				AAAA: net.ParseIP("2606:700:e:550::1")}},
		},
	}
	testDNSRecords = []*pb.DNSRecord{
		{
			Name:  "test",
			Type:  uint32(dns.TypeA),
			Value: "1.2.3.4",
			Zone:  "valid.zone.",
			Ttl:   50,
		},
		{
			Name:  "test",
			Type:  uint32(dns.TypeAAAA),
			Value: "2606:700:e:550::1",
			Zone:  "valid.zone.",
			Ttl:   90,
		},
	}
	testCfg = &pb.ServerConfig{}
)

func TestReadConf(t *testing.T) {

	// make an empty test file
	f, err := os.CreateTemp("", "env")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(f.Name())

	testCfg = ReadConf(DefaultConfig, f.Name())

	// check that the config is the same as the default config
	// using deepequal
	if !reflect.DeepEqual(testCfg, DefaultConfig) {
		fmt.Printf("config: %+v\n Default config: %+v", testCfg, DefaultConfig)
		t.Fatalf("config not equal to default config")
	}

	// now we set some stuff for later use
	testCfg.DnsConf.RootZones = []string{"valid.zone."}
}

func TestHandleDNS(t *testing.T) {
	TestReadConf(t)

	// initialize db with sqlmock
	txdb.Register("txdb", "pg",
		fmt.Sprintf(
			"postgres://%s:%s@%s/%s?sslmode=disable",
			testCfg.DBConf.GetUsername(), testCfg.DBConf.GetPassword(),
			testCfg.DBConf.GetHostname(), testCfg.DBConf.GetDatabaseName(),
		))

	tdb, err := sql.Open("txdb", "handleDNS")
	if err != nil {
		t.Fatalf(
			"an error '%s' was not expected when opening a stub database connection", err)
	}
	db, err := gorm.Open(postgres.New(postgres.Config{
		Conn: tdb,
	}))
	if err != nil {
		t.Fatalf(
			"an error '%s' was not expected when opening a stub database connection", err)
	}

	// migrate the schema
	db.AutoMigrate(&pb.DNSRecord{})

	// insert test data
	insertTestData(db, t)

	// start a DNS server
	h := DNSHandler{testCfg, db}
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", h.HandleDNS)
	srv := &dns.Server{Addr: testCfg.DnsConf.GetListenPort(), Net: "udp",
		Handler: dnsMux}

	go func() {
		panic(srv.ListenAndServe())
	}()
	time.Sleep(1 * time.Second)
	// run the tests
	for question, expected := range HandleDNSTests {
		// create a new dns message
		msg := new(dns.Msg)
		msg.SetQuestion(question.Name, question.Qtype)

		// send the message to the server
		resp, err := dns.Exchange(msg, "127.0.0.1"+testCfg.DnsConf.GetListenPort())
		if err != nil {
			t.Fatalf("error sending message to server: %v", err)
		}

		//fmt.Printf("response: %+v\n", testCfg)

		// set ID to 0 to make it easier to compare
		resp.Id = 0

		//fmt.Println(resp.Answer)

		// check the response with a deep reflection
		if !assert.Equalf(t, expected, resp, "response not equal to expected response: \n%+v\nExpected:\n%+v") {
			t.Fatalf("response not equal to expected response: \n%+v\nExpected:\n%+v",
				resp, expected)
		}

		fmt.Printf("Successfully tested question: %+v\n", question.Name)

	}

}

func insertTestData(db *gorm.DB, t *testing.T) {
	for _, record := range testDNSRecords {
		out := db.Create(record)
		fmt.Printf("added record: %+v\n", record)
		if out.Error != nil {
			t.Fatalf("error inserting test data: %v", out.Error)
		}
	}
}
