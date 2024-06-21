package restRouter

import (
	"bufio"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"whishper/authMsgGenerator"
	"whishper/storageApi"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt"
	"github.com/valyala/fasthttp"
)

type RestRouter struct {
	App         *fiber.App
	Storage     *storageApi.StorageApi
	connections map[string](chan string)
}

type UserClaims struct {
	Address string `json:"address"`
	jwt.StandardClaims
}

type User struct {
	IsRegistered bool   `json:"is_registered"`
	Address      string `json:"address"`    // hexString(md5( Marshaled pub key))
	PubKey       string `json:"pub_key"`    // b64 Marshaled PubKey
	PrivKey      string `json:"priv_key"`   // b64 Marshaled PrivbKey
	CreatedAt    int64  `json:"created_at"` // unix time
}

type UserLogin struct {
	Address   string `json:"address"`   // hexString(md5( Marshaled pub key))
	Signature string `json:"signature"` // b64 Address Signature
}

func (restRouter *RestRouter) generateKey(c *fiber.Ctx) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 512) // 64 Bytes
	if err != nil {
		c.Context().SetStatusCode(401)
		return err
	}

	publicKey := &privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privKeyB64 := base64.StdEncoding.EncodeToString(privKeyBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
	pubKeyMd5 := md5.Sum(pubKeyBytes)
	address := hex.EncodeToString(pubKeyMd5[:])
	redisKey := fmt.Sprintf("address/%s", address)
	user := User{IsRegistered: false, PubKey: pubKeyB64, Address: address}
	marshaledUser, err := json.Marshal(user)

	if err != nil {
		panic(err)
	}

	restRouter.Storage.Set(redisKey, string(marshaledUser))
	user.PrivKey = privKeyB64

	return c.JSON(user)
}

func (restRouter *RestRouter) registerKey(c *fiber.Ctx) error {
	userReq := UserLogin{}

	if err := c.BodyParser(&userReq); err != nil {
		c.Context().SetStatusCode(401)
		return err
	}
	redisKey := fmt.Sprintf("address/%s", userReq.Address)
	value, err := restRouter.Storage.Get(redisKey)
	if err != nil {
		return c.JSON(fiber.Map{"error": "Unauthorized"})
	}

	user := User{}
	if json.Unmarshal([]byte(value), &user) != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not unmarchal User"})
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(userReq.Signature)
	if err != nil || len(decodedSignature) == 0 {
		return c.JSON(fiber.Map{"error": "Unauthorized"})
	}

	derPubKey, err := base64.StdEncoding.DecodeString(user.PubKey)

	if err != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not decode pubKey from Redis : " + err.Error()})
	}

	pubKey, err := x509.ParsePKCS1PublicKey(derPubKey)
	if err != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not Parse PubKey : " + err.Error()})
	}

	if rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, []byte(user.Address), decodedSignature) != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not Verify Signature"})
	}

	user.IsRegistered = true
	marshaledUser, err := json.Marshal(user)

	if err != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not marshal User :" + err.Error()})
	}

	restRouter.Storage.Set(redisKey, string(marshaledUser))

	return c.JSON(user)
}

func (restRouter *RestRouter) login(c *fiber.Ctx) error {
	userReq := UserLogin{}
	if err := c.BodyParser(&userReq); err != nil {
		c.Context().SetStatusCode(401)
		return err
	}

	if userReq.Address == "" || userReq.Signature == "" {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "unauthorized"})
	}

	redisKey := fmt.Sprintf("address/%s", userReq.Address)
	value, err := restRouter.Storage.Get(redisKey)
	if err != nil {
		return c.JSON(fiber.Map{"error": "Unauthorized"})
	}

	user := User{}
	if json.Unmarshal([]byte(value), &user) != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not unmarchal User"})
	}

	derPubKey, err := base64.StdEncoding.DecodeString(user.PubKey)

	if err != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not decode pubKey from Redis : " + err.Error()})
	}

	pubKey, err := x509.ParsePKCS1PublicKey(derPubKey)
	if err != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not Parse PubKey : " + err.Error()})
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(userReq.Signature)
	if err != nil || len(decodedSignature) == 0 {
		return c.JSON(fiber.Map{"error": "Could not decode signature"})
	}

	auth := authMsgGenerator.Init()

	if rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, auth.Get().Sha256, decodedSignature) != nil {
		c.Context().SetStatusCode(401)
		return c.JSON(fiber.Map{"error": "Could not Verify Signature"})
	}

	claims := UserClaims{
		Address: userReq.Address,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
		}}

	// Create token.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("DEAD-BEEF-CAFE-FEACE"))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	fmt.Printf("Authenticated address %s\nGO Ahead %s\n", userReq.Address, t)

	return c.JSON(fiber.Map{"token": t})
}

func (restRouter *RestRouter) listen(c *fiber.Ctx) error {
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

	restRouter.connections[address] = make(chan string, 16)
	ch := restRouter.connections[address]

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	c.Status(fiber.StatusOK).Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		fmt.Println("Connected Address: " + address)
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

func (restRouter *RestRouter) postMsg(c *fiber.Ctx) error {
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
	// @ppierog : Fix this
	ch := restRouter.connections[payload.To]
	msg := fmt.Sprintf("{from:%s,msg:%s}\n", payload.From, payload.Msg)
	ch <- msg

	return c.JSON(fiber.Map{"status": "OK"})
}

func Init(storageApi *storageApi.StorageApi) RestRouter {

	// Fiber instance
	app := fiber.New()
	app.Config()

	// CORS for external resources
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Cache-Control",
		// AllowCredentials: true,
	}))

	restRouter := RestRouter{}
	restRouter.Storage = storageApi
	restRouter.connections = make(map[string](chan string))

	app.Post("/login", restRouter.login)
	app.Post("/generate", restRouter.generateKey)
	app.Post("/register", restRouter.registerKey)
	app.Post("/post", restRouter.postMsg)

	app.Get("/listen", restRouter.listen)

	restRouter.App = app

	return restRouter
}
