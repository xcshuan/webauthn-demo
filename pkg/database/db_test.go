package database

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	. "gopkg.in/check.v1"
	"os"
	"testing"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&dbSuite{})

type dbSuite struct {
}

func (s *dbSuite) SetUpTest(c *C) {
}

func (s *dbSuite) TestPut(c *C) {
	fp, err := os.CreateTemp("/tmp", "db_test")
	c.Assert(err, IsNil)
	defer func() {
		_ = os.Remove(fp.Name())
		_ = fp.Close()
	}()

	db, err := NewDb("file://" + fp.Name())
	c.Assert(err, IsNil)

	// put/get a user
	email := "foo1@test.com"
	err = db.PutUser(&User{
		Email:       email,
		DisplayName: "foo1",
		Credentials: nil,
	})
	c.Assert(err, IsNil)

	user, err := db.GetUser(email)
	c.Assert(err, IsNil)
	c.Assert(user.Email, Equals, email)

	// put user with credentials
	email = "withcreds@test.com"
	err = db.PutUser(&User{
		Email:       email,
		DisplayName: "foo1",
		Credentials: []webauthn.Credential{
			{
				ID:              []byte("0xdeadbeef"),
				PublicKey:       []byte("abcdefg"),
				AttestationType: "none",
				Transport:       []protocol.AuthenticatorTransport{"none"},
				Flags:           webauthn.CredentialFlags{},
				Authenticator:   webauthn.Authenticator{},
			},
		},
	})
	c.Assert(err, IsNil)

	user, err = db.GetUser(email)
	c.Assert(err, IsNil)
	c.Assert(user.Email, Equals, email)
	c.Assert(user.Credentials, NotNil)
}
