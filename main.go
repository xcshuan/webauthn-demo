package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
	"strings"
	"webauthn/pkg/database"
	"webauthn/pkg/session"
)

var webAuthn *webauthn.WebAuthn
var sessionStore *session.Store
var userDB *database.UserDB

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

func BeginRegistration(w http.ResponseWriter, r *http.Request) {

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
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = database.NewUser(username, displayName)
		userDB.PutUser(user)
	}

	// generate PublicKeyCredentialCreationOptions, session data
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		l.WithError(err).Error("BeginRegistration failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		l.WithError(err).Error("SaveWebauthnSession")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

// The browser calls this after browser asks user for creds or browser collects the private creds data from browser's store
func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("Finishregistration")

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("user not found")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishRegistration failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
	return
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("BeginLogin")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		l.WithError(err).Error("BeginLogin failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		l.WithError(err).Error("SaveWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("FinishLogin")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation we should perform additional
	// checks on the returned 'credential'
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishLogin failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

func main() {

	logrus.SetLevel(logrus.DebugLevel)

	listenAddr := "localhost:8080"

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName:        "Foobar Corp.",                   // display name for your site
		RPID:                 "localhost",                      // generally the domain name for your site
		RPOrigins:            []string{"http://" + listenAddr}, // The origin URLs allowed for WebAuthn requests
		EncodeUserIDAsString: false,                            // is/not URLEncodedBase64
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = database.DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./views")))

	log.Println("starting server at", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, r))
}
