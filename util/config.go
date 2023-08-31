package util

import (
	"database/sql"
	"os"

	pb "github.com/gidoBOSSftw5731/DeviceRegistrationSystem/proto"
	"github.com/subosito/gotenv"
	"github.com/uptrace/bun/driver/pgdriver"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	DefaultConfig = &pb.ServerConfig{
		DBConf: &pb.DatabaseConfig{
			Hostname:     "localhost:5432",
			Username:     "DRSUser",
			Password:     "BEAPROANDCHANGEME!",
			DatabaseName: "DRS",
		},
		DnsConf: &pb.DNSConfig{
			RootZones:  []string{"cshtest.clickable.systems."},
			ListenPort: ":5353",
			NsAddr:     "cshtestns.clickable.systems.",
			AdminEmail: "hostmaster.csh.rit.edu.",
		},
		ListenAddr: ":8090",
	}
)

// readConf is the function that scans environment variables for config arguments
// and then returns a config struct
// envPath is a list of paths to .env files to load if they aren't in your working directory
func ReadConf(defaultConfig *pb.ServerConfig, envPath ...string) *pb.ServerConfig {
	// Load environment variables from .env files
	err := gotenv.Load(envPath...)
	if err != nil {
		panic(err)
	}

	conf := defaultConfig
	// Read config from environment variables and replace default values if necessary
	for env, val := range map[string]*string{
		"DB_HOSTNAME":      &conf.DBConf.Hostname,
		"DB_USERNAME":      &conf.DBConf.Username,
		"DB_PASSWORD":      &conf.DBConf.Password,
		"LISTEN_ADDR":      &conf.ListenAddr,
		"DB_DATABASE_NAME": &conf.DBConf.DatabaseName,
		"DNS_ROOT_ZONE":    &conf.DnsConf.RootZones[0],
		"LISTEN_PORT":      &conf.DnsConf.ListenPort,
		"NS_ADDR":          &conf.DnsConf.NsAddr,
		"ADMIN_EMAIL":      &conf.DnsConf.AdminEmail,
	} {
		if os.Getenv(env) != "" {
			*val = os.Getenv(env)
		}
	}

	// Check zones for trailing period
	for _, zone := range append([]string{
		conf.DnsConf.GetNsAddr(),
		conf.DnsConf.GetAdminEmail(),
	}, conf.DnsConf.GetRootZones()...) {
		if zone[len(zone)-1] != '.' {
			zone += "."
		}
	}

	return conf
}

// confDB configures the database with a table for each of the structs used.
// All structs being used should originate from the pb package for standard access.
func ConfDB(dbConf *pb.DatabaseConfig) (*gorm.DB, error) {
	// Create the backend sql driver db for gorm to use.
	// this is the bun package but I can not be bothered to configure this again.
	// It just creates the backend database anyway, so it does not matter.
	sqldb := sql.OpenDB(pgdriver.NewConnector(
		pgdriver.WithAddr(dbConf.GetHostname()),
		pgdriver.WithUser(dbConf.GetUsername()),
		pgdriver.WithPassword(dbConf.GetPassword()),
		pgdriver.WithDatabase(dbConf.GetDatabaseName()),
	))

	db, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqldb,
	}))
	if err != nil {
		return nil, err
	}

	// create tables if they don't exist
	for _, v := range []interface{}{&pb.DNSRecord{}} {
		err = db.AutoMigrate(v)
		if err != nil {
			return nil, err
			//log.Errorln("Error migrating table: ", err)
		}
	}

	return db, nil
}
