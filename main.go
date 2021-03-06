package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"

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
	return ""
}

// Credentials owned by the user
func (this *User) WebAuthnCredentials() []webauthn.Credential {
	return this.creds
}

var keys = make(map[string]*User)
var registers = make(map[string]*webauthn.SessionData)
var logins = make(map[string]*webauthn.SessionData)

func newAuthn(c *gin.Context) (*webauthn.WebAuthn, error) {
	link, err := url.Parse(c.Request.Referer())
	if err != nil {
		return nil, err
	}

	hostname := link.Hostname()
	origin := link.String()
	link.Path = "favicon.ico"
	icon := link.String()

	auth, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         "Zuolar WebAuthn", // Display Name for your site
		RPID:                  hostname,          // Generally the FQDN for your site
		RPIcon:                icon,              // Optional icon URL for your site
		RPOrigin:              origin,            // The origin URL for WebAuthn requests
		Timeout:               1800000,
		Debug:                 true,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,             // ??????????????????(Platform)????????????USB????????????(Cross-Platform)
			UserVerification:        protocol.VerificationRequired, // ????????????????????????
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
	auth, err := newAuthn(c)
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		log.Println("==== ????????? ====", name)
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
	auth, err := newAuthn(c)
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		log.Println("==== ????????? ====")
		c.JSON(403, "not register")
		return
	}

	session := logins[user.WebAuthnName()]
	if session == nil {
		c.String(403, "Register Forbidden")
		return
	}

	cred, err := auth.FinishLogin(user, *session, c.Request)
	if err != nil {
		log.Printf("===== ???????????????????????? =====\n%+v\n", err)
		c.String(403, "Request Invalid: %s", err.Error())
		return
	}

	log.Println("======= ?????????????????? ========")
	id, _ := json.Marshal(cred.ID)
	pub, _ := json.Marshal(cred.PublicKey)
	log.Printf("ID = %s", string(id))
	log.Printf("PubKey = %s", string(pub))

	c.JSON(200, *cred)
}

func registerRequest(c *gin.Context) {
	auth, err := newAuthn(c)
	if err != nil {
		log.Printf("Create Authn Failed: %s\n", err.Error())
		c.String(500, "Create Authn Failed: %s", err.Error())
		return
	}

	opt := []webauthn.RegistrationOption{}
	name := c.Query("name")
	user, ok := keys[name]
	if !ok {
		user = newUser(name)
		keys[name] = user
	} else {
		ex := []protocol.CredentialDescriptor{}
		for _, cr := range user.WebAuthnCredentials() {
			ex = append(ex, protocol.CredentialDescriptor{
				CredentialID: cr.ID,
				Type:         protocol.PublicKeyCredentialType,
				Transport: []protocol.AuthenticatorTransport{
					protocol.Internal,
				},
			})
		}
		opt = append(opt, webauthn.WithExclusions(ex))
	}

	credOpt, session, err := auth.BeginRegistration(user, opt...)
	if err != nil {
		log.Printf("BeginRegistration Failed: %s\n", err.Error())
		c.String(200, "BeginRegistration Failed: %s", err.Error())
		return
	}

	registers[user.WebAuthnName()] = session
	// ????????????????????????????????????
	c.JSON(200, credOpt)
}

func registerResponse(c *gin.Context) {
	auth, err := newAuthn(c)
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
		log.Printf("===== ?????????????????? =====\n%+v\n", errors.Unwrap(err))
		c.String(200, "Request Invalid: %s", err.Error())
		return
	}

	log.Println("======= ?????????????????? ========")
	id, _ := json.Marshal(cred.ID)
	pub, _ := json.Marshal(cred.PublicKey)
	log.Printf("ID = %s", string(id))
	log.Printf("PubKey = %s", string(pub))
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
	log.Println("?????? => ", id)
	credID := []byte{}
	err := json.Unmarshal([]byte(`"`+id+`"`), &credID)
	if !ok {
		c.JSON(500, err)
		return
	}

	for i, cr := range user.creds {
		if bytes.Equal(cr.ID, credID) {
			log.Println("Got => ", i)
			user.creds = append(user.creds[:i], user.creds[i+1:]...)
			break
		}
	}

	c.JSON(200, nil)
}
