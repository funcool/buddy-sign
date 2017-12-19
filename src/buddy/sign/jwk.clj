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

(ns buddy.sign.jwk
  "JWK file reading writing and JCA conversions

   Supports only public/private key reading - no symmetric keys support available

   References:

   * https://tools.ietf.org/html/rfc7515
   * https://tools.ietf.org/html/rfc7517
   * https://tools.ietf.org/html/rfc7638
   * https://tools.ietf.org/html/rfc8037
   * https://www.iana.org/assignments/jose/jose.xhtml"
  (:require [clojure.java.io :as io]
            [cheshire.core :as json]
            [buddy.sign.jwk.proto :as proto]
            [buddy.sign.jwk.okp]
            [buddy.sign.jwk.ec]
            [buddy.sign.jwk.rsa]
            [buddy.sign.jwk.eddsa]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64])
  (:import (java.io StringReader StringWriter)
           (com.fasterxml.jackson.core JsonGenerator)
           (java.security KeyPair)))

(defn parse-file [path]
  (with-open [r (io/reader path)]
    (json/parse-stream r true)))

(defn parse-string [^String string]
  (let [r (StringReader. string)]
    (json/parse-stream r true)))

(defn jwk->private-key
  "Converts clojure map representing JWK object to java.security.PrivateKey"
  [jwk]
  (proto/jwk->private-key jwk))

(defn jwk->public-key
  "Converts clojure map representing JWK object to java.security.PublicKey"
  [jwk]
  (proto/jwk->public-key jwk))

(defn private-key->jwk
  "Converts JCA private and public key to clojure map representing JWK object"
  [private public]
  (proto/private-key->jwk private public))

(defn public-key->jwk
  "Converts JCA public key to clojure map representing JWK object"
  [public]
  (proto/public-key->jwk public))

(defn thumbprint
  "Calculates JWK thumbprint, returns bytes"
  [jwk]
  (proto/thumbprint jwk))

(defn write-file
  "Writes JWK object to file"
  [jwk path]
  (with-open [w (io/writer path)]
    (json/with-writer [w {}]
      (json/write jwk))))
