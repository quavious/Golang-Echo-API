package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/quavious/golang-prisma/model"
	"github.com/quavious/golang-prisma/prisma/db"
	"github.com/quavious/golang-prisma/util"
)

func main() {
	conn, err := model.DBPool()
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Disconnect()
	ctx := context.Background()

	app := echo.New()
	app.Use(middleware.Logger())
	app.Use(middleware.Recover())

	config := &middleware.JWTConfig{
		Claims:        &jwtCustomClaims{},
		SigningKey:    []byte("JWT_PASSWORD"),
		SigningMethod: "HS256",
		TokenLookup:   "cookie:x-token",
	}
	auth := middleware.JWTWithConfig(*config)

	app.GET("/api/user", func(c echo.Context) error {
		payload := c.Get("user").(*jwt.Token)
		claims := payload.Claims.(*jwtCustomClaims)
		userID := claims.ID
		user, err := conn.User.FindOne(
			db.User.ID.Equals(userID),
		).Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}
		if !user.Verified {
			return c.String(http.StatusBadRequest, "Check your email box.")
		}

		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"user":   user,
		})
	}, auth)

	app.POST("/api/register", func(c echo.Context) error {
		u := new(model.User)
		err := c.Bind(u)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}
		if len(u.Email) == 0 || len(u.Username) == 0 {
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		hash, err := u.PasswordHash()
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		created, err := conn.User.CreateOne(
			db.User.Email.Set(u.Email),
			db.User.Username.Set(u.Username),
			db.User.Password.Set(hash),
		).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}
		err = util.EmailVerify(ctx, &created)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status":   true,
			"response": "OK, Check your email box to verify your request.",
		})
	})

	app.GET("/api/regisier/verify", func(c echo.Context) error {
		id := c.QueryParam("id")
		token := c.QueryParam("token")

		if len(id) == 0 || len(token) == 0 {
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		userID, err := strconv.Atoi(id)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		req, err := conn.UserConfirm.FindOne(
			db.UserConfirm.ID.Equals(userID),
		).Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		if req.Token != token {
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		target := conn.User.FindOne(
			db.User.ID.Equals(userID),
		)

		temp, err := target.Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		if time.Now().After(req.Expired) {
			err = util.EmailVerify(ctx, &temp)
			if err != nil {
				log.Println(err)
				return c.String(http.StatusBadRequest, "Server ERROR")
			}
			return c.JSON(http.StatusBadRequest, echo.Map{
				"status": false,
				"msg":    "Email is being sent again.",
			})
		}
		_, err = target.Update(
			db.User.Verified.Set(true),
		).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"msg":    "You are now registered.",
		})
	})

	app.POST("/api/login", func(c echo.Context) error {
		u := new(model.User)
		err := c.Bind(u)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}
		found, err := conn.User.FindOne(
			db.User.Email.Equals(u.Email),
		).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}
		isMatch := u.PasswordCheck(found.Password)
		if !isMatch {
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		claims := &jwtCustomClaims{
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 3).Unix(),
			},
			found.ID,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		t, err := token.SignedString([]byte("JWT_PASSWORD"))

		cookie := new(http.Cookie)
		cookie.Name = "x-token"
		cookie.Value = t
		cookie.Expires = time.Now().Add(3 * time.Hour)
		c.SetCookie(cookie)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"status": "fail",
				"msg":    "Server Error",
			})
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status":   true,
			"response": "You are logged in.",
		})
	})

	app.POST("/api/user/delete", func(c echo.Context) error {
		payload := c.Get("user").(*jwt.Token)
		claims := payload.Claims.(*jwtCustomClaims)
		userID := claims.ID

		u := new(model.User)
		if err := c.Bind(u); err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		target, err := conn.User.FindOne(
			db.User.ID.Equals(userID),
		).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		isMatch := u.PasswordCheck(target.Password)
		if !isMatch {
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		_, err = conn.ExecuteRaw("DELETE FROM User WHERE id = ?", target.ID).Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"msg":    fmt.Sprintf("The User %s is removed", target.Username),
		})
	}, auth)

	app.POST("/api/user/update", func(c echo.Context) error {
		payload := c.Get("user").(*jwt.Token)
		claims := payload.Claims.(*jwtCustomClaims)
		userID := claims.ID

		u := new(model.User)
		if err := c.Bind(u); err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		target, err := conn.User.FindOne(
			db.User.ID.Equals(userID),
		).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		isMatch := u.PasswordCheck(target.Password)
		if !isMatch {
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		hash, err := u.PasswordHash()
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		_, err = conn.ExecuteRaw("UPDATE User set password = ? where id = ?", hash, userID).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Server ERROR")
		}

		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"msg":    fmt.Sprintf("The password of The User %s was updated", target.Username),
		})
	}, auth)

	app.POST("/api/post", func(c echo.Context) error {
		p := new(model.Post)
		if err := c.Bind(p); err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		payload := c.Get("user").(*jwt.Token)
		claims := payload.Claims.(*jwtCustomClaims)
		userID := claims.ID

		created, err := conn.Post.CreateOne(
			db.Post.Title.Set(p.Title),
			db.Post.Published.Set(true),
			db.Post.User.Link(
				db.User.ID.Equals(userID),
			),
			db.Post.Content.Set(p.Content),
			db.Post.AdLink.Set(p.AdLink),
		).Exec(ctx)

		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"msg":    (created.ID),
		})
	}, auth)

	app.GET("/api/post/all", func(c echo.Context) error {
		posts, err := conn.Post.FindMany().Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status":   true,
			"len":      len(posts),
			"response": posts,
		})
	})

	app.GET("/api/post/:id", func(c echo.Context) error {
		id := c.Param("id")
		postID, err := strconv.Atoi(id)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		post, err := conn.Post.FindOne(
			db.Post.ID.Equals(postID),
		).Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status":   true,
			"postId":   post.ID,
			"response": post,
		})
	})

	app.DELETE("/api/post/:id", func(c echo.Context) error {
		payload := c.Get("user").(*jwt.Token)
		claims := payload.Claims.(*jwtCustomClaims)
		userID := claims.ID

		id := c.Param("id")
		postID, err := strconv.Atoi(id)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		_, err = conn.ExecuteRaw("DELETE FROM Post WHERE id = ? and userId = ?", postID, userID).Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"msg":    fmt.Sprintf("The post %d was removed.", postID),
		})
	}, auth)

	app.PUT("/api/post/:id", func(c echo.Context) error {
		payload := c.Get("user").(*jwt.Token)
		claims := payload.Claims.(*jwtCustomClaims)
		userID := claims.ID

		id := c.Param("id")
		postID, err := strconv.Atoi(id)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		p := new(model.Post)
		if err := c.Bind(p); err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		_, err = conn.ExecuteRaw("UPDATE SET title = ?, content = ?, adLink = ? WHERE id = ? and userId = ?", p.Title, p.Content, p.AdLink, postID, userID).Exec(ctx)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status": true,
			"msg":    fmt.Sprintf("The post %d was updated.", postID),
		})
	}, auth)

	app.Logger.Fatal(app.Start("localhost:5000"))
}
