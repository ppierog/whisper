package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt"

	"github.com/valyala/fasthttp"
)

var index = []byte(`<!DOCTYPE html>
<html>
<body>

<h1>SSE Messages</h1>
<div id="result"></div>

<script>
if(typeof(EventSource) !== "undefined") {
  var source = new EventSource("http://127.0.0.1:3000/sse");
  source.onmessage = function(event) {
    document.getElementById("result").innerHTML += event.data + "<br>";
  };
} else {
  document.getElementById("result").innerHTML = "Sorry, your browser does not support server-sent events...";
}
</script>

</body>
</html>
`)

type UserClaims struct {
	Address string `json:"address"`
	jwt.StandardClaims
}

func generate(c *fiber.Ctx) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 128) // 64 Bytes
	if err != nil {

	}

	publicKey := &privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privKeyB64 := hex.EncodeToString(privKeyBytes)
	pubKeyB64 := hex.EncodeToString(pubKeyBytes)

	return c.JSON(fiber.Map{"privKey": privKeyB64, "pubKey": pubKeyB64})

	/*
	   privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	   privateKeyPEM := pem.EncodeToMemory(&pem.Block{
	   Type:  "RSA PRIVATE KEY",
	   Bytes: privateKeyBytes,
	   })

	        err = os.WriteFile("private.pem", privateKeyPEM, 0644)
	        if err != nil {

	        }

	        publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	        if err != nil {

	        }

	         publicKeyPEM := pem.EncodeToMemory(&pem.Block{
	           Type:  "RSA PUBLIC KEY",
	           Bytes: publicKeyBytes,
	         })

	        err = os.WriteFile("public.pem", publicKeyPEM, 0644)
	        if err != nil {

	        }
	*/
}

func listen(c *fiber.Ctx, addr string, ch chan string) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	c.Status(fiber.StatusOK).Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		fmt.Println("Connected Address: " + addr)
		var msg string
		for {

			select {
			case msg = <-ch:
				fmt.Println("Received msg : ")
				fmt.Println(msg)
				fmt.Fprintf(w, "data: message: %s\n", msg)

				err := w.Flush()
				if err != nil {
					// Refreshing page in web browser will establish a new
					// SSE connection, but only (the last) one is alive, so
					// dead connections must be closed here.
					fmt.Printf("Error while flushing: %v. Closing http connection.\n", err)

					// @Todo ppierog !!! Destroy channel here and remove from map !!!
					return
				}

			case <-time.After(time.Minute):
				fmt.Println("Timer expired doing flush")
				fmt.Fprint(w, "data: message: KEEP ALIVE\n")

				err := w.Flush()

				if err != nil {
					// Refreshing page in web browser will establish a new
					// SSE connection, but only (the last) one is alive, so
					// dead connections must be closed here.
					fmt.Printf("Error while flushing: %v. Closing http connection.\n", err)

					// @Todo ppierog !!! Destroy channel here and remove from map !!!
					return
				}

			}

		}
	}))

	return nil
}

func login(c *fiber.Ctx) error {
	payload := struct {
		Address  string `json:"address"`
		Password string `json:"password"`
	}{}

	if err := c.BodyParser(&payload); err != nil {
		c.Context().SetStatusCode(401)
		return err
	}

	if payload.Address == "" || payload.Password == "" {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "unauthorized"})
	}

	claims := UserClaims{
		Address: payload.Address,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
		}}

	// Create token.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	fmt.Printf("Authenticated address %s\nGO Ahead %s\n", payload.Address, t)

	return c.JSON(fiber.Map{"token": t})
}

func postMsg(c *fiber.Ctx, connections map[string]chan string) error {
	payload := struct {
		From string `json:"from"`
		To   string `json:"to"`
		Msg  string `json:"msg"`
	}{}

	if err := c.BodyParser(&payload); err != nil {
		c.Context().SetStatusCode(401)
		return err
	}

	if payload.From == "" || payload.To == "" || payload.Msg == "" {
		c.Context().SetStatusCode(404)
		return c.JSON(fiber.Map{"error": "Not found from/to address"})
	}

	ch := connections[payload.To]
	msg := fmt.Sprintf("{from:%s,msg:%s}\n", payload.From, payload.Msg)
	ch <- msg

	return c.JSON(fiber.Map{"status": "OK"})
}

func main() {

	connections := make(map[string](chan string))

	// Fiber instance
	app := fiber.New()
	app.Config()

	// CORS for external resources
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Cache-Control",
		// AllowCredentials: true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		c.Response().Header.SetContentType(fiber.MIMETextHTMLCharsetUTF8)
		return c.Status(fiber.StatusOK).Send(index)
	})

	app.Post("/login", login)

	app.Post("/generate", generate)

	app.Get("/listen", func(c *fiber.Ctx) error {
		var address string
		if t := c.Get("Authorization"); t != "" {

			res := strings.Fields(t)
			fmt.Printf("Listen Get Token :[%s]\n", res[1])
			parsedAccessToken, err := jwt.ParseWithClaims(res[1], &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte("secret"), nil
			})
			if err != nil {
				fmt.Printf("Could not Parse : [%s]\n", res[1])
				return nil
			}

			userClaims := parsedAccessToken.Claims.(*UserClaims)

			address = userClaims.Address
			fmt.Printf("Listen on Address: %s\n", address)

		}
		connections[address] = make(chan string, 16)
		return listen(c, address, connections[address])
	})

	app.Post("/postMsg", func(c *fiber.Ctx) error {

		return postMsg(c, connections)
	})

	// Start server
	log.Fatal(app.Listen(":3000"))
}
