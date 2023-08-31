package main

import (
	"net/http"
	"strings"

	"github.com/gidoBOSSftw5731/DeviceRegistrationSystem/util"
	"github.com/gidoBOSSftw5731/log"
	"gorm.io/gorm"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
)

// Handler is the struct that holds the server
type Handler struct{}

var (
	config *pb.ServerConfig
	db     *gorm.DB
)

func main() {
	// set log depth
	log.SetCallDepth(4)

	config = util.ReadConf(util.DefaultConfig, "../.env")

	var err error
	// configure database
	db, err = util.ConfDB(config.DBConf)
	if err != nil {
		log.Panicln(err)
	}

	s := &Handler{}

	log.Fatalln(http.ListenAndServe(config.GetListenAddr(), s))
}

// ServeHTTP is the function that handles the incoming requests
func (h *Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	// split request into parts
	URLSplit := strings.Split(req.URL.Path, "/")

	if len(URLSplit) < 3 {
		log.Errorln("Invalid request")
		resp.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check if the api version is correct:
	if URLSplit[1] != "v1" {
		log.Errorln("Invalid API version")
		resp.WriteHeader(http.StatusBadRequest)
		return
	}

	switch URLSplit[2] {
	case "addDNSRecord":
		// parse a POST form into a DNSRecord
		dnsRecord, err := util.ParseDNSRecord(req)
		if err != nil {
			log.Errorln(err)
			resp.WriteHeader(http.StatusBadRequest)
			return
		}
		db.Create(dnsRecord)
	}

}
