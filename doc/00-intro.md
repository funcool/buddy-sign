# Introduction

Buddy *sign* module is dedicated to provide a high level abstraction
for web ready message signing and encryption.

It can be used for several purposes:

* You can serialize and sign or encrypt a user ID for unsubscribing of
  newsletters into URLs. This way you don't need to generate one-time
  tokens and store them in the database.
* Same thing with any kind of activation link for accounts and similar things.
* Signed or encrypted objects can be stored in cookies or other
  untrusted sources which means you don't need to have sessions stored
  on the server, which reduces the number of necessary database
  queries.
* Signed information can safely do a roundtrip between server and
  client in general which makes them useful for passing server-side
  state to a client and then back.
* Safely send and receve signed or encrypted messages between
  components or microservices.
* Self contained token generation for use with completely stateless
  token based authentication.


## Install

The simplest way to use _buddy-sign_ in a clojure project, is by including it in the
dependency vector on your *_project.clj_* file:

```clojure
[buddy/buddy-sign "3.5.346"]
```

Or deps.edn:

```clojure
buddy/buddy-sign {:mvn/version "3.5.346"}
```

And is tested under JDK >= 8


## Involved RFC's?

* https://tools.ietf.org/html/rfc7519
* https://tools.ietf.org/html/rfc7518
* https://tools.ietf.org/html/rfc7516
* https://tools.ietf.org/html/rfc7515
* http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
* https://tools.ietf.org/html/rfc3394
* https://tools.ietf.org/html/rfc7517
* https://tools.ietf.org/html/rfc7638
* https://tools.ietf.org/html/rfc8037

## Source Code

_buddy-sign_ is open source and can be found on
[github](https://github.com/funcool/buddy-sign).

You can clone the public repository with this command:

```clojure
git clone https://github.com/funcool/buddy-sign
```

## Run tests

For running tests just execute this:

```clojure
lein test
```

## License

_buddy-sign_ is licensed under Apache 2.0 License. You can see the
complete text of the license on the root of the repository on
`LICENSE` file.
