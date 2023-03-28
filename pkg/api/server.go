package api

import (
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"webauthn/pkg/database"
	"webauthn/pkg/session"
)

type Server struct {
	listenAddr string
	mux        *mux.Router

	webAuthn     *webauthn.WebAuthn
	sessionStore *session.Store
	userDB       *database.UserDB
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
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = database.NewUser(username, displayName)
		s.userDB.PutUser(user)
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

	credential, err := s.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishRegistration failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
	return
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
	_, err = s.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishLogin failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

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
	logrus.Info("starting server at", s.listenAddr)
	logrus.Fatal(http.ListenAndServe(s.listenAddr, s.mux))
}

// NewServer
func NewServer(addr string) (*Server, error) {
	a := strings.Split(addr, ":")
	if len(a) != 2 {
		return nil, fmt.Errorf("requires hostname from listen address to provide as RPOrigin")
	}

	s := &Server{listenAddr: addr}

	var err error
	s.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName:        "Foobar Corp.",                     // display name for your site
		RPID:                 "localhost",                        // generally the domain name for your site
		RPOrigins:            []string{"http://" + s.listenAddr}, // The origin URLs allowed for WebAuthn requests
		EncodeUserIDAsString: false,                              // is/not URLEncodedBase64
	})

	if err != nil {
		return nil, fmt.Errorf("%w; failed to create WebAuthn from config", err)
	}

	s.userDB = database.DB()

	s.sessionStore, err = session.NewStore()
	if err != nil {
		return nil, fmt.Errorf("%w; failed to create session store", err)
	}

	r := mux.NewRouter()
	s.mux = r

	r.HandleFunc("/register/begin/{username}", s.beginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", s.finishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", s.beginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", s.finishLogin).Methods("POST")

	r.HandleFunc("/logout", s.logout).Methods("GET")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./views")))

	return s, nil
}
