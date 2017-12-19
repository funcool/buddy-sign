;; Copyright (c) 2014-2016 Andrey Antukh <niwi@niwi.nz>
;; Copyright (c) 2017 Denis Shilov <sxp@bk.ru>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.sign.jwk.rsa
  "JWK support for RSA keys"
  (:require [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [buddy.sign.jwk.proto :as proto]
            [cheshire.core :as json]
            [buddy.core.hash :as hash])
  (:import (java.security.interfaces RSAPrivateKey RSAPublicKey)
           (java.io StringWriter)
           (com.fasterxml.jackson.core JsonGenerator)
           (java.security KeyFactory)
           (java.security.spec RSAPrivateKeySpec RSAPublicKeySpec)))

(defmethod proto/jwk->private-key "RSA"
  [jwk]
  ;; TODO: add support for CRT representation (dp, dq, etc)
  ;; TODO: https://tools.ietf.org/html/rfc7517#section-9.3
  (let [n (proto/b64str->bigint (:n jwk))
        d (proto/b64str->bigint (:d jwk))
        kf (KeyFactory/getInstance "RSA" "BC")]
    (.generatePrivate kf (RSAPrivateKeySpec. n d))))

(defmethod proto/jwk->public-key "RSA"
  [jwk]
  (let [n (proto/b64str->bigint (:n jwk))
        e (proto/b64str->bigint (:e jwk))
        kf (KeyFactory/getInstance "RSA" "BC")]
    (.generatePublic kf (RSAPublicKeySpec. n e))))

(extend-protocol
  proto/ConvertPublicJCA
  RSAPublicKey
  (public-key->jwk [^RSAPublicKey public]
    (let [e (.getPublicExponent public)
          n (.getModulus public)]
      {:kty "RSA"
       :e   (proto/bigint->b64str (proto/calc-byte-length e) e)
       :n   (proto/bigint->b64str (proto/calc-byte-length n) n)})))

(extend-protocol
  proto/ConvertPrivateJCA
  RSAPrivateKey
  (private-key->jwk [^RSAPrivateKey private ^RSAPublicKey public]
    (let [d (.getPrivateExponent private)
          n (.getModulus private)
          e (.getPublicExponent public)
          ;; Use public modulus to calculate byte length
          l (proto/calc-byte-length n)]
      {:kty "RSA"
       :e   (proto/bigint->b64str (proto/calc-byte-length e) e)
       :n   (proto/bigint->b64str l n)
       :d   (proto/bigint->b64str l d)})))

;; https://tools.ietf.org/html/rfc7638#section-3.1
(defmethod proto/thumbprint "RSA"
  [jwk]
  (let [w (StringWriter.)
        jg ^JsonGenerator (json/create-generator w)]
    (doto jg
      (.writeStartObject)
      (.writeStringField "e" (:e jwk))
      (.writeStringField "kty" (:kty jwk))
      (.writeStringField "n" (:n jwk))
      (.writeEndObject)
      (.flush))
    (hash/sha256 (str w))))
