# AspNetCore.HmacAuthentication
HMAC authorization system for ASP.NET Core

Authenticate HTTP requests by using the HMAC authentication scheme. (HMAC refers to hash-based message authentication code.) These requests must be transmitted over TLS.

## Prerequisites

- **Credential** - \<Access Key ID\>
- **Secret** - base64 decoded Access Key Value. ``base64_decode(<Access Key Value>)``


Provide each request with all HTTP headers required for authentication. The minimum required are:

|  Request Header | Description  |
| --------------- | ------------ |
| **Host** | Internet host and port number. [HTTP Host Header Specification (RFC 7230)](https://datatracker.ietf.org/doc/html/rfc7230) |
| **Date** | Date and time at which the request was originated. It can't be more than 15 minutes off from the current Coordinated Universal Time (Greenwich Mean Time). [HTTP Date Header Specification (RFC 9110)](https://datatracker.ietf.org/doc/html/rfc9110) |
| **Content-Digest** | Cryptographic digest (hash) of the request body. It must be provided even if there is no body. [HTTP Content-Digest Specification (RFC 9530)](https://www.ietf.org/rfc/rfc9530.html) |
| **Authorization** | Authentication information required by the HMAC scheme. Format and details are explained later in this article. [HTTP Authorization Header Specification (IETF)](https://www.ietf.org/archive/id/draft-ietf-httpbis-p7-auth-11.html) |

**Example:**

```http
Host: api.example.com
Date: Fri, 11 May 2018 18:48:36 GMT
Content-Digest: sha-256={SHA256 hash of the request body}
Authorization: HMAC Credential={Access Key ID}&SignedHeaders=Date;Host;Content-Digest&Signature={Signature}
```

## Authorization header

### Syntax

``Authorization``: **HMAC** ```Credential```=\<value\>&```SignedHeaders```=\<value\>&```Signature```=\<value\>

|  Argument | Description  |
| ------ | ------ |
| **HMAC** | Authorization scheme. _(required)_ |
| **Credential** | The ID of the access key used to compute the signature. _(required)_ |
| **SignedHeaders** | HTTP request headers added to the signature. _(required)_ |
| **Signature** | base64 encoded HMACSHA256 of String-To-Sign. _(required)_|

### Credential

ID of the access key used to compute the signature.

### Signed headers

HTTP request header names, separated by semicolons, required to sign the request. These HTTP headers must be correctly provided with the request as well. Don't use white spaces.

### Required HTTP request headers

`Date`;`Host`;`Content-Digest`

Any other HTTP request headers can also be added to the signing. Just append them to the ```SignedHeaders``` argument.

**Example:**

Date;Host;Content-Digest;```Content-Type```;```Accept```

### Signature

Base64 encoded HMACSHA256 hash of the String-To-Sign. It uses the access key identified by `Credential`. 

`base64_encode(HMACSHA256(String-To-Sign, Secret))`

### String-To-Sign

It is a canonical representation of the request:

_String-To-Sign=_

**HTTP_METHOD** + '\n' +
**path_and_query** + '\n' +
**signed_headers_values**

|  Argument | Description  |
| ------ | ------ |
| **HTTP_METHOD** | Uppercase HTTP method name used with the request. [HTTP Methods Specification](https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1) |
|**path_and_query** | Concatenation of request absolute URI path and query string. [HTTP URI Path and Query String Specification](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3) |
| **signed_headers_values** | Semicolon-separated list of all HTTP request header values specified in SignedHeaders, presented in the order they appear. |

**Example:**

```js
string-To-Sign=
            "GET" + '\n' +                                                                     // VERB
            "/kv?fields=*&api-version=1.0" + '\n' +                                            // path_and_query
            "Fri, 11 May 2018 18:48:36 GMT;api.example.com;{value of Content-Digest header}"   // signed_headers_values
```


