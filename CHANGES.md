# Changelog

## Version 3.4.333

Date: 2022-01-14

- Update dependencies.


## Version 3.4.1

Date: 2021-05-02

- Update buddy-core to 1.10.1


## Version 3.4.0

Date: 2021-05-01

- Update buddy-core to 1.10.0


## Version 3.3.0

Date: 2020-12-03

- Update buddy-core to 1.9.0
- Update nippy to 3.1.1 (provided)


## Version 3.2.0

Date: 2020-09-15

- Update buddy-core to 1.8.0


## Version 3.1.0

Date: 2019-06-28

- Update buddy-core to 1.6.0


## Version 3.0.0

- Update buddy-core to 1.5.0
- Proper handling of SignatureException (jws).
- Add EdDSA signer.
- Add KeyProvider abstraction for enably dynamic selection
  of key on JWS.


## Version 2.2.0

Date: 2017-08-29

- Update buddy-core to 1.4.0


## Version 2.1.0

Date: 2017-08-28

- Add `:skip-validation` option to **jwt** functions, for allow inspect invalid tokens.
- Add support for custom header through `:header` option on jws, jwe and jwt.
- The `typ` header is no longer set by default (is optional on the RFC
  and is removed for save some bytes on all tokens)
- Now only the `:alg` and `:enc` headers are treated specially
  (keywordized on header decoding), tha rest are returned as is.


## Version 2.0.0

Date: 2017-08-08

- Stop rejecting tokens with future `:iat` claim values. (BACKWARD
  INCOMPATIBLE CHANGE, more info in [#49](https://github.com/funcool/buddy-sign/pull/49))
- Fix unexpected exception in some malformed tokens.
- Add `:leeway` option to `jwt/unsign` function.
- Update buddy-core to 1.3.0


## Version 1.6.0

Date: 2017-07-28

- Update to use Clojure 1.9-alpha17
- Update cheshire to 5.7.1
- Update nippy to 2.13.0
- Allows not just a single issuer, but also a collection of issuers,
  to be provided for validating the `iss` claim in a token

## Version 1.5.0

Date: 2017-03-30

- Evaluate jdk8 extensions at runtime. It allow build jdk7 compatible
  jars using JDK8.


## Version 1.4.0

Date: 2017-01-24

- Update buddy-core to 1.2.0
- Update cheshire to 5.7.0


## Version 1.3.0

Date: 2016-11-15

- Update buddy-core to 1.1.1


## Version 1.2.0

Date: 2016-08-28

- Update buddy-core to 1.0.0
- Update cheshire to 5.6.3
- Update nippy to 2.12.2
- Add the ability to pass any type that implements ITimestamp protocol
  as value to the `:now` parameter on JWT api.


## Version 1.1.0

Date: 2016-06-10

- Test everything with generative tests (with test.check)
- Drop direct support to clojure 1.5 and 1.6
  (because test.check has hard dependency with clojure ># 1.7)
- Update to buddy 0.13.0 that fixes some bugs that affects
  to JWE when compressed tokens are used.
- Fix varios jwe/jws/jwt validations bugs found thanks to using
  generative tests with test.check.
- The `aud` claim validation can be a set.


## Version 1.0.0

Date: 2016-05-20

**Important**: This is an major release beacause it includes breaking api changes.

Important changes:

**JWS and JWE becomes a more low level function** for sign or encrypt arbitrary
data (as RFC specifies) and all claims and json related stuff is moved into
specific **JWT** related namespace.

The api is preserved so, the migration is pretty easy; just replace your `jws` or
`jwe` import with `jwt`.

[source, clojure]
----
;; Old imports:
(require '[buddy.sign.jws :as jws])
(require '[buddy.sign.jwe :as jwe])

;; New import:
(require '[buddy.sign.jwt :as jwt])
----

Many thanks to @FreekPaans for the initial work on split JWS and JWT.

The **clj-time** dependency is removed. JodaTime directly is used if it is
avaliable in the classpath.

Add jdk8 java.time.Instant support for time related claims.

Removed hardcoded dependency to `nippy` for compact signing ns. Now the user
should specify their own dependency in order to be able use the compact message
signing implementation.


## Version 0.13.0

Date: 2016-04-24

- Fix unexpected NPE on header parsing on jws/jwe.
- Fixed `:exp` claim validation (thanks @dottedmag) for JWS/JWE.
- Fixed `:nbf` claim validation on JWE.
- Add improved `:iat` validation (thanks @dottedmag) for JWS/JWE.


## Version 0.12.0

Date: 2016-04-08

- Fix compliance with RFC bug in JWE implementation (header was improperly encoded
  before passed as aad that causes incompatibilities with other implementations).
  WARNING: will invalidate all your tokens.
- Adapt to buddy-core api changes.


## Version 0.11.0

Date: 2016-03-27

- Update buddy-core dependency to 0.11.0
- Remove user.clj accindentally pulled into the jar.


## Version 0.10.0

Date: 2016-03-26

- Update buddy-core dependency to 0.10.0
- Update nippy dependency to 2.11.1.
- Fix exception data inconsistency with jwt on compact impl.
- Fix wrong documentation about auto detection of the alg.


## Version 0.9.0

Date: 2016-01-06

- Update buddy-core dependency to 0.9.0
- Minor cosmetic changes.


## Version 0.8.1

Date: 2015-11-17

- Properly remove cats dependency.
- Fix wrong arguments on jws and compact sign methods.


## Version 0.8.0

Date: 2015-11-15

- Adapt to buddy-core 0.8.x changes.
- BREAKING CHANGE: Remove cats dependency.
  The jws/encode, jws/decode and respectivelly functions
  in the jwe namespace are now simple alias to the main
  api on the each ns.


## Version 0.7.1

Date: 2015-09-23

- Fix broken nbf claim validation.
  (thanks to @jonpither for report it)


## Version 0.7.0

Date: 2015-09-19

- Update cats to 1.0.0
- Update clj-time to 0.11.0
- Update nippy to 2.9.1
- Update buddy-core to 0.7.0
- Remove slingshot usage and start using plain
  clojure.lang.ExceptionInfo exceptions.
  (maybe breaking change)


## Version 0.6.1

Date: 2015-08-02

* Set default clojure version to 1.7.0
* Update cats version to 0.6.1


## Version 0.6.0

Date: 2015-06-28

* Replace cryptographic primitives used in jwe implementation
  with buddy-core new implementation that fixes few bugs realted
  to wrong padding management.
* Update buddy-core to 0.6.0
* Remove direct slingshot dependency because is not transitive
  from the new buddy-core version.
* Update cheshire dependency to 5.5.0


## Version 0.5.1

Date: 2015-05-09

* Improved error reporting when validating wrong jwe/jws tokens.


## Version 0.5.0

Date: 2015-04-03

* Add Jsen Web Encryption support. With key encryption algorithms:  `DIR`, `A128KW`, `A192KW`, `A256KW`,
  `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`. and content encryption algorithms: `A128CBC-HS256`,
  `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`, `A192GCM`, `A256GCM`.
* The encode and decode functions now returns instances of success or failure of exception monad
  instead of instances of either monad (maybe breaking change).
* The sign and unsign functions now raises exceptions instead of simply return nil. This allows
  libraries and applications that does not works with monads workis like a usual, using jvm
  exceptions and know the specific error instead of useless nil (maybe breaking change).
* Add the ability to specify the `:typ` header value in JWS.
* Add :iss (issuer) and :aud (audience) claims validation to JWS.
* Add explicit alg validation in JWS (the previous behavior that only checks the header alg without
  matching it with user provided value has security flaws:
  https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/


## Version 0.4.2

Date: 2015-03-29

* Bug fix related to :iat param validating on jws. (thanks to @tvanhens)


## Version 0.4.1

Date: 2015-03-14

* Update nippy version from 2.7.1 to 2.8.0
* Update buddy-core from 0.4.0 to 0.4.2
* Update cats from 0.3.2 to 0.3.4


## Version 0.4.0

Date: 2015-02-22

* Add encode/decode functions to JWS/JWT implementation. Them instead of return
  plain value, return a monadic either. That allows granular error reporting
  instead something like nil that not very useful. The previous sign/unsign
  are conserved for backward compatibility but maybe in future will be removed.
* Rename parameter `maxage` to `max-age` on jws implementation. This change
  introduces a little backward incompatibility.
* Add "compact" signing implementation as replacemen of django based one.
* Django based generic signing is removed.
* Update buddy-core version to 0.4.0


## Version 0.3.0

Date: 2014-01-18

* First version splitted from monolitic buddy package.
* No changes from original version.
