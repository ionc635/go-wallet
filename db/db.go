package db

import (
	"database/sql"
	"time"

	conf "lecture/go-wallet/config"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
)

var config = conf.GetConfig("config/config.toml")

var (
	User   = config.Mysql.User
	Passwd = config.Mysql.Passwd
	Addr   = config.Mysql.Addr
	DBName = config.Mysql.DBName
)

func GetConnector() *sql.DB {
	cfg := mysql.Config{
		User:                 User,
		Passwd:               Passwd,
		Net:                  "tcp",
		Addr:                 Addr,
		Collation:            "utf8mb4_general_ci",
		Loc:                  time.UTC,
		MaxAllowedPacket:     4 << 20.,
		AllowNativePasswords: true,
		CheckConnLiveness:    true,
		DBName:               DBName,
	}
	connector, err := mysql.NewConnector(&cfg)
	if err != nil {
		panic(err)
	}
	db := sql.OpenDB(connector)
	return db
}
