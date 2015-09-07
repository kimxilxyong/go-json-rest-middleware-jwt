This is a fork of StephanDollberg/go-json-rest-middleware-jwt with the intent to return more detailed auth errors in the JSON return data, including errors from dgrijalva/jwt-go.

Example return from curl:

```
>curl -i -H "Authorization:Bearer eyJhbGci ...... wMzM"  http://localhost:8080/somejwt/login

HTTP/1.1 401 Unauthorized
Content-Type: application/json
Www-Authenticate: JWT realm=HolyRealm
X-Powered-By: go-json-rest
Date: Mon, 07 Sep 2015 02:35:41 GMT
Content-Length: 103

{
  "Error": "Not Authorized",
  "JwtValidationCode": 8,
  "JwtValidationMessage": "token is expired"
}
```

Its considered alpha, the functionality is implemented but no testcases yet.
Debug Printf's need to be removed - but if you try it, it should not burn down your house.

The following text is from the original: [StephanDollberg/go-json-rest-middleware-jwt](https://github.com/StephanDollberg/go-json-rest-middleware-jwt)

JWT Middleware for Go-Json-Rest
==================================

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/StephanDollberg/go-json-rest-middleware-jwt) [![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/StephanDollberg/go-json-rest-middleware-jwt/master/LICENSE)

This is a middleware for [Go-Json-Rest](https://github.com/ant0ine/go-json-rest).

It uses [jwt-go](https://github.com/dgrijalva/jwt-go) to provide a jwt authentication middleware. It provides additional handler functions to provide the login api that will generate the token and an additional refresh handler that can be used to refresh tokens.

An example can be found in the [Go-Json-Rest Examples](https://github.com/ant0ine/go-json-rest-examples/tree/master/jwt) repo.

