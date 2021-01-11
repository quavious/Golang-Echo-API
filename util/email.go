package util

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/quavious/golang-prisma/model"
	"github.com/quavious/golang-prisma/prisma/db"
	"gopkg.in/gomail.v2"
)

// EmailVerify figures out that email being send is valid.
func EmailVerify(ctx context.Context, user *db.UserModel) error {
	byteSource := make([]byte, 32)
	_, err := rand.Read(byteSource)
	if err != nil {
		return err
	}
	token := url.QueryEscape(base64.StdEncoding.EncodeToString(byteSource))
	conn, _ := model.DBPool()

	expired := time.Now().Add(time.Hour * 3)
	_, err = conn.UserConfirm.CreateOne(
		db.UserConfirm.ID.Set(user.ID),
		db.UserConfirm.Token.Set(token),
		db.UserConfirm.Expired.Set(expired),
	).Exec(ctx)

	m := gomail.NewMessage()

	m.SetHeader("From", "Email Address")

	// Set E-Mail receivers
	m.SetHeader("To", user.Email)

	// Set E-Mail subject
	m.SetHeader("Subject", "Email Vetification TEST")

	urlConfirm := fmt.Sprintf("http://localhost:5000/api/regisier/verify?id=%d&token=%s", user.ID, token)
	// Set E-Mail body. You can set plain text or html with text/html
	m.SetBody("text/html", fmt.Sprintf(`<a href="%s">%s</>`, urlConfirm, urlConfirm))

	// Settings for SMTP server
	d := gomail.NewDialer("Email SMTP Server Address", 587, "Email Account ID", "Email Account Password")

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Now send E-Mail
	if err := d.DialAndSend(m); err != nil {
		log.Println(err)
		return err
	}
	return nil
}
