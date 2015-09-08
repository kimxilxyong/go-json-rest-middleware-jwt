// Package jwt provides Json-Web-Token authentication for the go-json-rest framework
package jwt

import (
	//"errors"
	"fmt"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// JWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userId is made available as
// request.Env["REMOTE_USER"].(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type JWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// Sets the debug level: 0=none, 1=errors, 2=warnings, 3=infos
	DebugLevel int

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required.
	Key []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on userId and
	// password. Must return true on success, false on failure. Required.
	Authenticator func(userId string, password string) bool

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(userId string, request *rest.Request) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via request.Env["JWT_PAYLOAD"].
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(userId string) map[string]interface{}
}

// The errors that might occur inside auth_jwt and not inside dgrijalva/jwt-go
const (
	AuthJwtErrorNotValidYet uint32 = jwt.ValidationErrorNotValidYet << iota // error const start after jwt errors
	AuthJwtErrorLoginFailed
	AuthJwtErrorAuthorizationFailed // Login failed
	AuthJwtErrorInternalError
)

// MiddlewareFunc makes JWTMiddleware implement the Middleware interface.
func (mw *JWTMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {

	// DEBUG
	fmt.Printf("*************************** MiddlewareFunc\n")
	fmt.Printf("*************************** test error code jwt.ValidationErrorNotValidYet %s\n", jwt.ValidationErrorNotValidYet)
	fmt.Printf("*************************** test error code AuthJwtErrorNotValidYet %s\n", AuthJwtErrorNotValidYet)
	fmt.Printf("*************************** test error code AuthJwtErrorLoginFailed %s\n", AuthJwtErrorLoginFailed)
	fmt.Printf("*************************** test error code AuthJwtErrorInternalError %s\n", AuthJwtErrorInternalError)
	if mw.Realm == "" {
		log.Fatal("Realm is required")
	}
	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}
	if mw.Key == nil {
		log.Fatal("Key required")
	}
	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}
	if mw.Authenticator == nil {
		log.Fatal("Authenticator is required")
	}
	if mw.Authorizator == nil {
		mw.Authorizator = func(userId string, request *rest.Request) bool {
			return true
		}
	}

	return func(writer rest.ResponseWriter, request *rest.Request) { mw.middlewareImpl(writer, request, handler) }
}

func (mw *JWTMiddleware) middlewareImpl(writer rest.ResponseWriter, request *rest.Request, handler rest.HandlerFunc) {

	// DEBUG
	fmt.Printf("*************************** middlewareImpl\n")

	token, err := mw.parseToken(request)

	if err != nil {
		// DEBUG
		fmt.Printf("*** EXIT ** PARSETOKENS ERROR *** middlewareImpl: %s\n", err.Error())
		fmt.Printf("*** EXIT ** PARSETOKENS ERROR ***** TypeOf error: %s\n", reflect.TypeOf(err))

		mw.unauthorized(writer, err)
		return
	}

	id := token.Claims["id"].(string)

	request.Env["REMOTE_USER"] = id
	request.Env["JWT_PAYLOAD"] = token.Claims

	if mw.DebugLevel > 2 {
		fmt.Printf("REMOTE_USER: %s\n", request.Env["REMOTE_USER"])
		fmt.Printf("REMOTE_USER: %v\n", request.Env["JWT_PAYLOAD"])
	}

	if !mw.Authorizator(id, request) {
		mw.unauthorized(writer, &AuthJwtError{err: "user " + id + " not authorized for request " + request.URL.String(), ErrorCode: AuthJwtErrorAuthorizationFailed})
		return
	}

	fmt.Printf("*** ------------------ ******************** middlewareImpl PAYLOAD before: %s\n", request.Env["JWT_PAYLOAD"])

	handler(writer, request)

	fmt.Printf("*** ------------------ ******************** middlewareImpl PAYLOAD after: %s\n", request.Env["JWT_PAYLOAD"])
}

// Helper function to extract the JWT claims
func ExtractClaims(request *rest.Request) map[string]interface{} {

	// DEBUG
	fmt.Printf("*************************** ExtractClaims")

	if request.Env["JWT_PAYLOAD"] == nil {
		empty_claims := make(map[string]interface{})
		return empty_claims
	}
	jwt_claims := request.Env["JWT_PAYLOAD"].(map[string]interface{})
	return jwt_claims
}

type login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// An error generated by the auth jwt middleware, not by dgrijalva/jwt-go
type AuthJwtError struct {
	err       string
	ErrorCode uint32 // numeric error, see jwt.ValidationError... constants
}

// AuthJwtError error is an error type
func (e AuthJwtError) Error() string {
	return e.err
}

// Handler that clients can use to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) LoginHandler(writer rest.ResponseWriter, request *rest.Request) {

	// DEBUG
	fmt.Printf("*************************** LoginHandler\n")

	login_vals := login{}
	err := request.DecodeJsonPayload(&login_vals)

	if err != nil {
		// DEBUG
		fmt.Printf("*** LoginHandler Error: %s\n", err.Error())
		mw.unauthorized(writer, err)
		return
	}

	if !mw.Authenticator(login_vals.Username, login_vals.Password) {
		mw.unauthorized(writer, &AuthJwtError{err: "login failed", ErrorCode: AuthJwtErrorLoginFailed})
		return
	}
	// DEBUG
	fmt.Printf("*** Before LoginHandler GetSigningMethod: %s\n", mw.SigningAlgorithm)
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	fmt.Printf("*** After LoginHandler GetSigningMethod: %s\n", mw.SigningAlgorithm)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(login_vals.Username) {
			token.Claims[key] = value
		}
	}

	token.Claims["id"] = login_vals.Username
	token.Claims["exp"] = time.Now().Add(mw.Timeout).Unix()
	if mw.MaxRefresh != 0 {
		token.Claims["orig_iat"] = time.Now().Unix()
	}

	tokenString, err := token.SignedString(mw.Key)
	if err != nil {
		mw.unauthorized(writer, err)
		return
	}

	writer.WriteJson(&map[string]string{"token": tokenString})
}

func (mw *JWTMiddleware) parseToken(request *rest.Request) (*jwt.Token, error) {

	// DEBUG
	fmt.Printf("* parseToken : %v\n", request.Header)

	authHeader := request.Header.Get("Authorization")

	// DEBUG
	fmt.Printf("* parseToken Header: %v\n", request.Header)

	if authHeader == "" {
		//return nil, errors.New("Auth header empty")
		return nil, &AuthJwtError{err: "auth header empty", ErrorCode: jwt.ValidationErrorMalformed}
	}

	// DEBUG
	fmt.Printf("* parseToken authHeader: %v\n", authHeader)

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		//return nil, errors.New("Invalid auth header")
		return nil, &AuthJwtError{err: "invalid auth header", ErrorCode: jwt.ValidationErrorMalformed}
	}

	return jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != token.Method {
			//return nil, errors.New("Invalid signing algorithm")
			return nil, &AuthJwtError{err: "invalid signing algorithm", ErrorCode: jwt.ValidationErrorUnverifiable}
		}
		return mw.Key, nil
	})
}

type token struct {
	Token string `json:"token"`
}

// Handler that clients can use to refresh their token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the JWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) RefreshHandler(writer rest.ResponseWriter, request *rest.Request) {

	// DEBUG
	fmt.Printf("*************************** RefreshHandler : %v\n", request.Env)

	token, err := mw.parseToken(request)

	// Token should be valid anyway as the RefreshHandler is authed
	if err != nil {

		// DEBUG
		fmt.Printf("* parse: %v\n", err.Error())
		mw.unauthorized(writer, err)
		return
	}

	origIat := int64(token.Claims["orig_iat"].(float64))

	if origIat < time.Now().Add(-mw.MaxRefresh).Unix() {
		mw.unauthorized(writer, err)
		return
	}

	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))

	for key := range token.Claims {
		newToken.Claims[key] = token.Claims[key]
	}

	newToken.Claims["id"] = token.Claims["id"]
	newToken.Claims["exp"] = time.Now().Add(mw.Timeout).Unix()
	newToken.Claims["orig_iat"] = origIat
	tokenString, err := newToken.SignedString(mw.Key)

	if err != nil {
		mw.unauthorized(writer, err)
		return
	}

	writer.WriteJson(&map[string]string{"token": tokenString})
}

func (mw *JWTMiddleware) unauthorized(writer rest.ResponseWriter, err error) {

	// DEBUG
	fmt.Printf("* unauthorized\n")

	writer.Header().Set("WWW-Authenticate", "JWT realm="+mw.Realm)
	errorMsg := "not authorized"

	var JwtValidationMessage string
	var JwtValidationCode uint32

	if err != nil {

		switch err.(type) {
		case *jwt.ValidationError:
			fmt.Printf("*** EXIT ** PARSETOKENS ERROR ***** IS *jwt.ValidationError !!)")
			if ve, ok := err.(*jwt.ValidationError); ok {
				JwtValidationMessage = ve.Error()
				JwtValidationCode = ve.Errors
			}
		case *AuthJwtError:
			fmt.Printf("*** EXIT ** PARSETOKENS ERROR ***** IS *AuthJwtError !!)")
			if ae, ok := err.(*AuthJwtError); ok {
				JwtValidationMessage = ae.Error()
				JwtValidationCode = ae.ErrorCode
			}
		default:
			JwtValidationMessage = err.Error()
			JwtValidationCode = AuthJwtErrorInternalError
		}
	}
	writer.WriteHeader(http.StatusUnauthorized)
	err = writer.WriteJson(map[string]interface{}{
		"Error":                errorMsg,
		"JwtValidationMessage": JwtValidationMessage,
		"JwtValidationCode":    JwtValidationCode})
	if err != nil {
		panic(err)
	}
}
