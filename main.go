package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gin-gonic/gin"
)

// https://codelabs.developers.google.com/codelabs/webauthn-reauth/#2
// https://glitch.com/edit/#!/insidious-stump-psychology?path=public%2Fclient.js%3A64%3A5

var _ webauthn.User = &User{}

type User struct {
	name  string
	creds []webauthn.Credential
}

func newUser(name string) *User {
	return &User{
		name:  name,
		creds: []webauthn.Credential{},
	}
}

// User ID according to the Relying Party
func (this *User) WebAuthnID() []byte {
	return []byte(this.name)
}

// User Name according to the Relying Party
func (this *User) WebAuthnName() string {
	return this.name
}

// Display Name of the user
func (this *User) WebAuthnDisplayName() string {
	return this.name
}

// User's icon url
func (this *User) WebAuthnIcon() string {
	return rpIcon
}

// Credentials owned by the user
func (this *User) WebAuthnCredentials() []webauthn.Credential {
	return this.creds
}

var keys = make(map[string]*User)
var registers = make(map[string]*webauthn.SessionData)
var logins = make(map[string]*webauthn.SessionData)

const rpIcon = "https://8cbbf92b9e64.ngrok.io/favicon.ico"

func newAuthn() (*webauthn.WebAuthn, error) {
	auth, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         "Zuolar WebAuthn",               // Display Name for your site
		RPID:                  "8cbbf92b9e64.ngrok.io",         // Generally the FQDN for your site
		RPIcon:                rpIcon,                          // Optional icon URL for your site
		RPOrigin:              "https://8cbbf92b9e64.ngrok.io", // The origin URL for WebAuthn requests
		Timeout:               1800000,
		Debug:                 true,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,             // 想用裝置指紋(Platform)，或者是USB安全金鑰(Cross-Platform)
			UserVerification:        protocol.VerificationRequired, // 若用指紋，則必填
		},
	})
	if err != nil {
		return nil, err
	}

	return auth, nil
}

// Your initialization function
func main() {
	r := gin.Default()
	r.GET("/registerRequest", registerRequest)
	r.POST("/registerResponse", registerResponse)
	r.GET("/loginRequest", loginRequest)
	r.Any("/loginResponse", loginResponse)
	r.GET("/getKeys", getKeys)
	r.GET("/removeKeys", removeKeys)
	r.NoRoute(gin.WrapH(http.FileServer(http.Dir("./"))))
	_ = r.Run(":3000")
}

func loginRequest(c *gin.Context) {
	auth, err := newAuthn()
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		log.Println("==== 未註冊 ====", name)
		c.JSON(200, "not register")
		return
	}

	cred, session, err := auth.BeginLogin(user)
	if err != nil {
		log.Printf("BeginLogin Failed: %s\n", err.Error())
		c.String(500, "BeginLogin Failed: %s", err.Error())
		return
	}

	logins[user.WebAuthnName()] = session
	c.JSON(200, cred)
}

func loginResponse(c *gin.Context) {
	auth, err := newAuthn()
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		log.Println("==== 未註冊 ====")
		c.JSON(200, "not register")
		return
	}

	session := logins[user.WebAuthnName()]
	if session == nil {
		c.String(403, "Register Forbidden")
		return
	}

	cred, err := auth.FinishLogin(user, *session, c.Request)
	if err != nil {
		log.Printf("===== 解析登入憑證失敗 =====\n%+v\n", err)
		c.String(200, "Request Invalid: %s", err.Error())
		return
	}

	log.Println("======= 憑證登入成功 ========")
	log.Printf("%#v", *cred)
	c.JSON(200, *cred)
}

func registerRequest(c *gin.Context) {
	auth, err := newAuthn()
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	name := c.Query("name")
	user := newUser(name)

	credOpt, session, err := auth.BeginRegistration(user)
	if err != nil {
		log.Printf("BeginRegistration Failed: %s\n", err.Error())
		c.String(200, "BeginRegistration Failed: %s", err.Error())
		return
	}

	keys[name] = user
	registers[user.WebAuthnName()] = session
	// 回傳給前端建立憑證的參數
	c.JSON(200, credOpt)
}

func registerResponse(c *gin.Context) {
	auth, err := newAuthn()
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		c.String(403, "User Forbidden")
		return
	}

	session := registers[user.WebAuthnName()]
	if session == nil {
		c.String(403, "Register Forbidden")
		return
	}

	cred, err := auth.FinishRegistration(user, *session, c.Request)
	if err != nil {
		log.Printf("===== 解析憑證失敗 =====\n%+v\n", errors.Unwrap(err))
		c.String(200, "Request Invalid: %s", err.Error())
		return
	}

	log.Println("======= 解析憑證成功 ========")
	log.Printf("%#v", *cred)
	user.creds = append(user.creds, *cred)

	c.JSON(200, cred)
}

func getKeys(c *gin.Context) {
	user, ok := keys[c.Query("name")]
	if !ok {
		c.JSON(200, []int{})
		return
	}

	c.JSON(200, user.WebAuthnCredentials())
}

func removeKeys(c *gin.Context) {
	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		c.JSON(200, nil)
		return
	}

	id := c.Query("cred")

	for i, cr := range user.creds {
		if string(cr.ID) == id {
			user.creds = append(user.creds[:i], user.creds[i+1:]...)
			break
		}
	}

	c.JSON(200, nil)
}
