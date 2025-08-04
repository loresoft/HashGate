# AspNetCore.HmacAuthentication

HMAC authorization system for ASP.NET Core

Authenticate HTTP requests by using the HMAC authentication scheme. (HMAC refers to hash-based message authentication code.) These requests must be transmitted over TLS.

## Prerequisites

-   **Client** - \<Access Key ID\>
-   **Secret** - base64 decoded Access Key Value. `base64_decode(<Access Key Value>)`

Provide each request with all HTTP headers required for authentication. The minimum required are:

| Request Header       | Description                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Host**             | Internet host and port number.                                                                                                             |
| **x-timestamp**      | Date and time at which the request was originated. It can't be more than 15 minutes off from the current Coordinated Universal Time (GMT). |
| **x-content-sha256** | base64 encoded SHA256 hash of the request body.. It must be provided even if there is no body.                                             |
| **Authorization**    | Authentication information required by the HMAC scheme. Format and details are explained later in this article.                            |

**Example:**

```http
Host: api.example.com
x-timestamp: Fri, 11 May 2018 18:48:36 GMT
x-content-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
Authorization: HMAC Client=123456789&SignedHeaders=host;x-timestamp;x-content-sha256&Signature={Signature}
```

## Authorization header

### Syntax

`Authorization`: **HMAC** `Client`=\<value\>&`SignedHeaders`=\<value\>&`Signature`=\<value\>

| Argument          | Description                                                          |
| ----------------- | -------------------------------------------------------------------- |
| **HMAC**          | Authorization scheme. _(required)_                                   |
| **Client**    | The ID of the access key used to compute the signature. _(required)_ |
| **SignedHeaders** | HTTP request headers added to the signature. _(required)_            |
| **Signature**     | base64 encoded HMACSHA256 of String-To-Sign. _(required)_            |

### Client

ID of the access key used to compute the signature.

### Signed headers

HTTP request header names, separated by semicolons, required to sign the request. These HTTP headers must be correctly provided with the request as well. Don't use white spaces.

### Required HTTP request headers

`Host`;`x-timestamp`;`x-content-sha256`

Any other HTTP request headers can also be added to the signing. Just append them to the `SignedHeaders` argument.

**Example:**

Host;x-timestamp;x-content-sha256;`Content-Type`;`Accept`

### Signature

Base64 encoded HMACSHA256 hash of the String-To-Sign. It uses the access key identified by `Client`.

`base64_encode(HMACSHA256(String-To-Sign, Secret))`

### String-To-Sign

It is a canonical representation of the request:

_String-To-Sign=_

**HTTP_METHOD** + '\n' +
**path_and_query** + '\n' +
**signed_headers_values**

| Argument                  | Description                                                                                                                |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **HTTP_METHOD**           | Uppercase HTTP method name used with the request.                                                                          |
| **path_and_query**        | Concatenation of request absolute URI path and query string.                                                               |
| **signed_headers_values** | Semicolon-separated list of all HTTP request header values specified in SignedHeaders, presented in the order they appear. |

**Example:**

```js
string-To-Sign=
    "GET" + '\n' +                                                                                  // VERB
    "/kv?fields=*&api-version=1.0" + '\n' +                                                         // path_and_query
    "api.example.com;Fri, 11 May 2018 18:48:36 GMT;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="    // signed_headers_values
```

## Reference

- [Azure HMAC Authentication](https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac)
- [AWS Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
