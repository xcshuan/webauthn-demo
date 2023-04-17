package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
	"webauthn/pkg/database"
	"webauthn/pkg/jwt"
	"webauthn/pkg/session"
	"webauthn/pkg/webauthnContract"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	jwt2 "github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Server the WebAuthn "Relying Party" implementation
type Server struct {
	href       string
	listenAddr string
	mux        *mux.Router

	webAuthn     *webauthn.WebAuthn
	sessionStore *session.Store
	userDB       *database.UserDB

	chainID          *big.Int
	client           *ethclient.Client
	webauthnAddr     common.Address
	webauthnContract *webauthnContract.WebauthnContract
	webauthnAbi      abi.ABI
	privKey          *ecdsa.PrivateKey
	address          common.Address

	// jwtSvc to create a JWT bearer token sent on response to /login
	jwtSvc *jwt.JWT
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)

	logrus.WithField("httpStatusCode", c).Debug(string(dj))
}

// the browser javascript calls this after the user presses the `Register` button
func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	l := logrus.WithField("username", username)
	l.Debug("BeginRegistration")

	// get user
	user, err := s.userDB.GetUser(username)
	// user doesn't exist, create new user
	// WARN: only if you want to allow auto registration of any user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = database.NewUser(username, displayName)
		if err := s.userDB.PutUser(user); err != nil {
			jsonResponse(w, fmt.Errorf(err.Error()), http.StatusBadRequest)
			return
		}
	}

	// generate PublicKeyCredentialCreationOptions, session data
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		l.WithError(err).Error("BeginRegistration failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = s.sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		l.WithError(err).Error("SaveWebauthnSession")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

// The browser javascript calls this after browser asks user for creds or browser collects the private creds data from browser's store
func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("Finishregistration")

	// get user
	user, err := s.userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("user not found")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := s.sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		l.WithError(err).Error("parse error")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	credential, err := s.webAuthn.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		l.WithError(err).Error("FinishRegistration failed")
		extra := err.(*protocol.Error).DevInfo
		jsonResponse(w, err.Error()+"\n"+extra, http.StatusBadRequest)
		return
	}

	appID, err := parsedResponse.GetAppID(sessionData.Extensions, credential.AttestationType)
	if err != nil {
		l.WithError(err).Error("parse error")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var (
		key interface{}
	)
	// If the Session Data does not contain the appID extension or it wasn't reported as used by the Client/RP then we
	// use the standard CTAP2 public key parser.
	if appID == "" {
		key, err = webauthncose.ParsePublicKey(credential.PublicKey)
	} else {
		key, err = webauthncose.ParseFIDOPublicKey(credential.PublicKey)
	}

	switch k := key.(type) {
	case webauthncose.OKPPublicKeyData:
	case webauthncose.EC2PublicKeyData:
		pubKeyX := new(big.Int).SetBytes(k.XCoord)
		pubKeyY := new(big.Int).SetBytes(k.YCoord)
		auth, err := s.genAuth(r.Context())
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		transaction, err := s.webauthnContract.RegisterP256Key(auth,
			username,
			hex.EncodeToString(credential.ID),
			pubKeyX,
			pubKeyY)
		s.SendTransactionAndWait(r.Context(), transaction)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
	case webauthncose.RSAPublicKeyData:
		n := k.Modulus
		e := k.Exponent
		auth, err := s.genAuth(r.Context())
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		transaction, err := s.webauthnContract.RegisterRSAKey(auth,
			username,
			hex.EncodeToString(credential.ID),
			n,
			e)
		s.SendTransactionAndWait(r.Context(), transaction)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
	default:
		l.WithError(err).Error("parse error")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	credentialJson, _ := json.Marshal(credential)
	println("userName:", username)
	rpIDHash := sha256.Sum256([]byte(s.webAuthn.Config.RPID))
	println("rpIDHash:", s.webAuthn.Config.RPID, hex.EncodeToString(rpIDHash[:]))
	println("credential:", string(credentialJson))
	println("AAGUID:", credential.Authenticator.AAGUID)
	println("pubkey length:", len(credential.PublicKey))

	user.AddCredential(*credential)
	if err := s.userDB.PutUserCredentials(user); err != nil {
		jsonResponse(w, fmt.Errorf(err.Error()), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {
	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("BeginLogin")

	// get user
	user, err := s.userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		l.WithError(err).Error("BeginLogin failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = s.sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		l.WithError(err).Error("SaveWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("FinishLogin")

	// get user
	user, err := s.userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := s.sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation we should perform additional
	// checks on the returned 'credential'
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		l.WithError(err).Error("FinishLogin failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := s.webAuthn.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		l.WithError(err).Error("FinishLogin failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	appID, err := parsedResponse.GetAppID(sessionData.Extensions, credential.AttestationType)
	if err != nil {
		l.WithError(err).Error("parse error")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var (
		key interface{}
	)
	// If the Session Data does not contain the appID extension or it wasn't reported as used by the Client/RP then we
	// use the standard CTAP2 public key parser.
	if appID == "" {
		key, err = webauthncose.ParsePublicKey(credential.PublicKey)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
	} else {
		key, err = webauthncose.ParseFIDOPublicKey(credential.PublicKey)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}

	clientDataJson, _ := base64.RawURLEncoding.DecodeString(parsedResponse.Raw.AssertionResponse.ClientDataJSON.String())

	fmt.Println("ClientDataJSON: ", string(clientDataJson))
	indexA := bytes.Index(clientDataJson, []byte(`challenge":"`))
	indexB := bytes.Index(clientDataJson[indexA+12:], []byte("\""))
	fmt.Println("indexA", indexA, string(clientDataJson[indexA+12:indexA+12+indexB]))
	clientDataJsonPre := clientDataJson[:indexA+12]
	clientDataJsonPost := clientDataJson[indexA+12+indexB:]
	challengeBase64 := clientDataJson[indexA+12 : indexA+12+indexB]
	println(string(clientDataJsonPre))
	println(string(challengeBase64))
	println(string(clientDataJsonPost))

	challenge, err := base64.RawURLEncoding.DecodeString(string(challengeBase64))
	if err != nil {
		l.WithError(err).Error("decode error")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}
	println("challenge len", len(challenge))

	switch key.(type) {
	case webauthncose.OKPPublicKeyData:
	case webauthncose.EC2PublicKeyData:
		type ECDSASignature struct {
			R, S *big.Int
		}
		e := &ECDSASignature{}
		_, err := asn1.Unmarshal(parsedResponse.Raw.AssertionResponse.Signature, e)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		auth, err := s.genAuth(r.Context())
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		transaction, err := s.webauthnContract.AuthenticateUseES256(
			auth,
			username,
			e.R,
			e.S,
			challenge,
			[]byte(parsedResponse.Raw.AssertionResponse.AuthenticatorData),
			clientDataJsonPre,
			clientDataJsonPost,
		)
		s.SendTransactionAndWait(r.Context(), transaction)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
	case webauthncose.RSAPublicKeyData:
		auth, err := s.genAuth(r.Context())
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		transaction, err := s.webauthnContract.AuthenticateUseRS256(
			auth,
			username,
			parsedResponse.Response.Signature,
			challenge,
			[]byte(parsedResponse.Raw.AssertionResponse.AuthenticatorData),
			clientDataJsonPre,
			clientDataJsonPost,
		)
		s.SendTransactionAndWait(r.Context(), transaction)
		if err != nil {
			l.WithError(err).Error("parse error")
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		// callData, err := s.webauthnAbi.Pack(
		// 	"authenticateUseRS256",
		// 	username,
		// 	parsedResponse.Response.Signature,
		// 	[]byte(parsedResponse.Raw.AssertionResponse.AuthenticatorData),
		// 	[]byte(parsedResponse.Raw.AssertionResponse.ClientDataJSON),
		// )
		// if err != nil {
		// 	l.WithError(err).Error("parse error")
		// 	jsonResponse(w, err.Error(), http.StatusUnauthorized)
		// 	return
		// }
		// gasPrice, err := s.client.SuggestGasPrice(r.Context())
		// if err != nil {
		// 	l.WithError(err).Error("suggest gasPrice error")
		// 	jsonResponse(w, err.Error(), http.StatusUnauthorized)
		// 	return
		// }
		// res, err := s.client.CallContract(r.Context(), ethereum.CallMsg{
		// 	From:      s.address,
		// 	To:        &s.webauthnAddr,
		// 	Gas:       1000000,
		// 	GasPrice:  gasPrice,
		// 	GasFeeCap: gasPrice,
		// 	GasTipCap: gasPrice,
		// 	Value:     big.NewInt(0),
		// 	Data:      callData,
		// }, nil)
		// fmt.Println("res: ", res, "err: ", err)
	default:
		l.WithError(err).Error("parse error")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// create a JWT bearer token and add to the header response
	claims := jwt2.MapClaims{"iss": s.href}
	token := s.jwtSvc.SignClaims(claims, time.Now().Add(5*time.Minute))
	w.Header().Set("Authorization", "Bearer "+token)

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("Logout")

	// TODO how do we know this is for the same user that's passed in?

	if err := s.sessionStore.DeleteWebauthnSession("authentication", r, w); err != nil {
		logrus.WithError(err).Error("DeleteWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResponse(w, "Logout Success", http.StatusOK)
}

// Start
func (s *Server) Start() {
	logrus.Info("starting server at:", s.listenAddr)
	logrus.Fatal(http.ListenAndServe(s.listenAddr, s.mux))
}

func (s *Server) genAuth(ctx context.Context) (*bind.TransactOpts, error) {
	gasPrice, err := s.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(s.privKey, s.chainID)
	if err != nil {
		return nil, err
	}

	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(1000000) // in units
	auth.GasPrice = gasPrice
	var nonce uint64
	nonce, err = s.client.NonceAt(ctx, s.address, nil)
	if err != nil {
		return nil, err
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.NoSend = true

	return auth, nil
}

func (s *Server) SendTransactionAndWait(ctx context.Context, tx *types.Transaction) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	l := logrus.WithField("txHash", tx.Hash())
	for {
		err := s.client.SendTransaction(ctx, tx)
		if err != nil {
			// 判断交易是否已经上链了
			receipt, err := s.client.TransactionReceipt(ctx, tx.Hash())
			if err == nil {
				if receipt.Status == 1 {
					l.Infof("Tx: %s execute success", tx.Hash())
				} else {
					l.Infof("Tx: %s execute failed", tx.Hash())
				}
				return
			}
			// 否则继续尝试发送
			l.Error("SendTransaction:", tx.Hash(), " failed, retrying.....")
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	l.Infof("Send Tx: %s to node success, waiting finality", tx.Hash())
	// 等100 ms
	time.Sleep(100 * time.Millisecond)
	retryCount := 0
	for {
		receipt, err := s.client.TransactionReceipt(ctx, tx.Hash())
		if err == nil {
			if receipt.Status == 1 {
				l.Infof("Tx: %s execute success", tx.Hash())
			} else {
				l.Infof("Tx: %s execute failed", tx.Hash())
			}
			return
		}
		if err == ethereum.NotFound {
			if retryCount < 5 {
				l.Error("TransactionReceipt:", tx.Hash(), " not found, retrying.....")
				retryCount++
				time.Sleep(2 * time.Second)
				continue
			}
		}
		l.Errorf("Tx: %s get receipt error: %s", tx.Hash(), err)
		return
	}
}

// NewServer
func NewServer(addr string, client *ethclient.Client, contractAddr common.Address, privKeyStr string) (*Server, error) {
	a := strings.Split(addr, ":")
	if len(a) != 2 {
		return nil, fmt.Errorf("requires hostname from listen address to provide as RPOrigin")
	}

	s := &Server{
		listenAddr: addr,
		href:       "http://" + addr,
	}
	var err error
	s.webauthnAbi, err = abi.JSON(strings.NewReader(webauthnContract.WebauthnContractABI))
	if err != nil {
		return nil, err
	}
	webauthnContract, err := webauthnContract.NewWebauthnContract(contractAddr, client)
	if err != nil {
		return nil, err
	}

	privKey, err := crypto.HexToECDSA(strings.TrimPrefix(privKeyStr, "0x"))
	if err != nil {
		return nil, err
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		panic(err)
	}

	s.client = client
	s.webauthnAddr = contractAddr
	s.webauthnContract = webauthnContract
	s.privKey = privKey
	s.chainID = chainID
	publicKey := privKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		logrus.Panic("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	s.address = crypto.PubkeyToAddress(*publicKeyECDSA)

	if err != nil {
		return nil, err
	}

	s.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName:        "Foobar Corp.",   // display name for your site
		RPID:                 "localhost",      // generally the domain name for your site
		RPOrigins:            []string{s.href}, // The origin URLs allowed for WebAuthn requests
		EncodeUserIDAsString: false,            // is/not URLEncodedBase64
	})

	if err != nil {
		return nil, fmt.Errorf("%w; failed to create WebAuthn from config", err)
	}

	s.userDB, err = database.NewDb("file:./users.db")
	if err != nil {
		return nil, err
	}

	s.sessionStore, err = session.NewStore()
	if err != nil {
		return nil, fmt.Errorf("%w; failed to create session store", err)
	}

	r := mux.NewRouter()
	s.mux = r

	// webauthn endpoints
	r.HandleFunc("/register/begin/{username}", s.beginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", s.finishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", s.beginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", s.finishLogin).Methods("POST")

	r.HandleFunc("/logout", s.logout).Methods("GET")

	// to sign JWT bearer token - considering this could be the only authorization flow
	s.jwtSvc, err = jwt.NewJWT("./TestCertificate.crt")
	if err != nil {
		return nil, err
	}
	jwks := s.jwtSvc.NewJWKService()
	r.HandleFunc("/well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks.WriteResponse(w, r)
	}).Methods(http.MethodGet)

	// for static pages e.g. javascript
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./views")))

	return s, nil
}
