package model

import (
	"github.com/quavious/golang-prisma/prisma/db"
)

var conn *db.PrismaClient = db.NewClient()
var err error = conn.Connect()

// DBPool gives one db connection pool.
func DBPool() (*db.PrismaClient, error) {
	return conn, err
}
