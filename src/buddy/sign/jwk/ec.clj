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

(ns buddy.sign.jwk.ec
  (:require [buddy.core.keys]
            [buddy.sign.jwk.proto :as proto]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [cheshire.core :as json]
            [buddy.core.hash :as hash])
  (:import (java.security.interfaces ECPublicKey ECPrivateKey ECKey)
           (java.security SecureRandom KeyPairGenerator AlgorithmParameters KeyFactory)
           (java.security.spec ECGenParameterSpec ECPoint ECParameterSpec ECPrivateKeySpec ECPublicKeySpec)
           (java.io StringWriter)
           (com.fasterxml.jackson.core JsonGenerator)
           (org.apache.commons.codec.binary Base64)))

;; EC type - curve specific
(defmulti jwkec->public-key :crv)
(defmulti jwkec->private-key :crv)

(defmethod proto/jwk->public-key "EC"
  [jwk]
  (jwkec->public-key jwk))

(defmethod proto/jwk->private-key "EC"
  [jwk]
  (jwkec->private-key jwk))

(defn- load-private [jwk curvename]
  (let [d (proto/b64str->bigint (:d jwk))
        ap (AlgorithmParameters/getInstance "EC" "BC")
        _ (.init ap (ECGenParameterSpec. curvename))
        spec (.getParameterSpec ap ECParameterSpec)
        kf (KeyFactory/getInstance "EC" "BC")]
    ;; TODO: check private and public key match
    (.generatePrivate kf (ECPrivateKeySpec. d spec))))

(defn- load-public [jwk curvename]
  (let [x (proto/b64str->bigint (:x jwk))
        y (proto/b64str->bigint (:y jwk))
        ep (ECPoint. x y)
        ap (AlgorithmParameters/getInstance "EC" "BC")
        _ (.init ap (ECGenParameterSpec. curvename))
        spec (.getParameterSpec ap ECParameterSpec)
        kf (KeyFactory/getInstance "EC" "BC")]
    (.generatePublic kf (ECPublicKeySpec. ep spec))))

(defmethod jwkec->private-key "P-256"
  [jwk]
  (load-private jwk "P-256"))

(defmethod jwkec->public-key "P-256"
  [jwk]
  (load-public jwk "P-256"))

(defmethod jwkec->private-key "P-384"
  [jwk]
  (load-private jwk "P-384"))

(defmethod jwkec->public-key "P-384"
  [jwk]
  (load-public jwk "P-384"))

(defmethod jwkec->private-key "P-521"
  [jwk]
  (load-private jwk "P-521"))

(defmethod jwkec->public-key "P-521"
  [jwk]
  (load-public jwk "P-521"))

(defn- get-curve [curvename]
  (let [sr (SecureRandom/getInstance "SHA1PRNG")
        kg (KeyPairGenerator/getInstance "EC" "BC")]
    (.initialize kg (ECGenParameterSpec. curvename) sr)
    (.getCurve (.getParams ^ECPublicKey (.getPublic (.generateKeyPair kg))))))

;; the best way i've found to convert PublicKey params to EC Name
;; is by using equals on Curve field (it checks curve params for equality)
(def ^:private p256curve (get-curve "P-256"))
(def ^:private p384curve (get-curve "P-384"))
(def ^:private p521curve (get-curve "P-521"))

(defn- get-curve-name [^ECKey key]
  (let [curve (.getCurve (.getParams key))]
    (condp = curve
      p256curve
      "P-256"
      p384curve
      "P-384"
      p521curve
      "P-521"
      ;; default
      (throw (ex-info "Unsupported EC curve (only P-256, P-384 and P-521 supported)"
                      {:key key})))))

(defn- convert-public [^ECPublicKey public]
  (let [w (.getW public)
        x (.getAffineX w)
        y (.getAffineY w)
        ;; Use public X to calculate byte length
        l (proto/calc-byte-length x)]
    {:kty "EC"
     :crv (get-curve-name public)
     :x   (proto/bigint->b64str l x)
     :y   (proto/bigint->b64str l y)}))

(extend-protocol proto/ConvertPublicJCA
  ECPublicKey
  (public-key->jwk [^ECPublicKey public]
    (convert-public public)))

(extend-protocol proto/ConvertPrivateJCA
  ECPrivateKey
  (private-key->jwk [^ECPrivateKey private ^ECPublicKey public]
    (let [public (convert-public public)
          d (.getS private)
          l (proto/calc-byte-length d)]
      (assoc public :d (proto/bigint->b64str l d)))))

;; https://tools.ietf.org/html/rfc7638#section-3.2
(defmethod proto/thumbprint "EC"
  [jwk]
  (let [w (StringWriter.)
        jg ^JsonGenerator (json/create-generator w)]
    (doto jg
      (.writeStartObject)
      (.writeStringField "crv" (:crv jwk))
      (.writeStringField "kty" (:kty jwk))
      (.writeStringField "x" (:x jwk))
      (.writeStringField "y" (:y jwk))
      (.writeEndObject)
      (.flush))
    (hash/sha256 (str w))))
