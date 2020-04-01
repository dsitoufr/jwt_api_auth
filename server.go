package main

import (
	"log"
	"fmt"
	"net/http"
	//jwt go library
	"github.com/dgrijalva/jwt-go"
	"encoding/json"
	"time"
	"github.com/gorilla/mux"
)


// Create a struct to read the username and password from the request body
type credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Create a struct that will be encoded to a JWT.
type Claims struct {
	Username string `json:"username,omitempty"`
	jwt.StandardClaims
}

var (
	users map[string]string
	jwtkey []byte
)


func main() {

	// Init router
	router := mux.NewRouter()

	//init map
	users = make(map[string]string)
	jwtkey = []byte ("mOn SEcRt")
	
	users["user1"] = "password1"
	users["user2"] = "password2"


	router.HandleFunc("/api/signing",signing).Methods("POST")
	router.HandleFunc("/api/welcome",welcome).Methods("POST")
	router.HandleFunc("/api/welcome",refresh).Methods("POST")
	log.Println("starting server...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

//handling functions

func signing(response http.ResponseWriter, request *http.Request) {
	var creds credentials
	
	// Get the JSON body and decode into credentials
	err:= json.NewDecoder(request.Body).Decode(&creds)
    if err != nil {
		//body struct is wrong
		log.Fatal(err)
	}
	log.Println("body decoded.")
	// Get the expected password from our in memory map
	expectedPassword, ok := users[creds.Username]
	
	if !ok || expectedPassword != creds.Password {
		response.WriteHeader(http.StatusUnauthorized)
	    return
	}
	log.Println("password matched.")

	// Declare the expiration time of the token
	expirationTime := time.Now().Add(( 5 * time.Minute))

	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//declare token with algorithm used for siging, and claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//create JWT string
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println("created JWT string")

	//set client cookie for token as the JWT generated
	//also set expiration time same as the token
	//If a user logs in with the correct credentials, 
	//this handler will then set a cookie on the client side with the JWT value.
	http.SetCookie(response, &http.Cookie{
		Name: "token",
		Value: tokenString,
		Expires: expirationTime,
	})
	log.Println("client cookie setted.")


	//Now that all logged in clients have session information 
	//stored on their end as cookies, we can use it to welcomed, refresh..
}

func welcome(response http.ResponseWriter, request *http.Request) {
//we get  session token from resquest cookie
resultCookie, err := request.Cookie("token")
if err != nil {
	  if err == http.ErrNoCookie {
		  //cookie not set
		  response.WriteHeader(http.StatusUnauthorized)
		  return
	  }
	  //others error
	  response.WriteHeader(http.StatusBadRequest)
	  return
}

//get JWT string from cookie
tknStr := resultCookie.Value

//new instance of claims
claims := &Claims{}

//parse JWT string with key and store results in cleam
// Note that we are passing the key in this method as well. This method will return an error
// if the token is invalid (if it has expired according to the expiry time we set on sign in),
// or if the signature does not match

tkn, err := jwt.ParseWithClaims(tknStr, claims, 
	    func(token *jwt.Token) (interface{}, error) {
		    return jwtkey, nil
	})

if err != nil {
	if err == jwt.ErrSignatureInvalid {
		 response.WriteHeader(http.StatusUnauthorized)
		 return
	}

	response.WriteHeader(http.StatusBadRequest)
	return
}

if !tkn.Valid {
	response.WriteHeader(http.StatusUnauthorized)
	return
}

//Finally return welcom message to the user
response.Write([]byte(fmt.Sprintf("Welcome  %s!", claims.Username)))
}

func refresh(response http.ResponseWriter, request * http.Request) {
  
	//we get  session token from resquest cookie
resultCookie, err := request.Cookie("token")
if err != nil {
	  if err == http.ErrNoCookie {
		  //cookie not set
		  response.WriteHeader(http.StatusUnauthorized)
		  return
	  }
	  //others error
	  response.WriteHeader(http.StatusBadRequest)
	  return
}

tknStr := resultCookie.Value
claims := &Claims{}

tkn, err := jwt.ParseWithClaims(tknStr, claims, 
	  func(token *jwt.Token)(interface{}, error){
		  return jwtkey, nil
	  })

	  if err != nil {
		  if err == jwt.ErrSignatureInvalid {
			  response.WriteHeader(http.StatusUnauthorized)
              return 
			}
			
			  response.WriteHeader(http.StatusBadRequest)
	          return
	   }
	//expired ?
	if ! tkn.Valid {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	//set new token  as user cookie
	http.SetCookie(response, &http.Cookie{
		Name: "token",
		Value: tokenString,
		Expires: expirationTime,
	})
}