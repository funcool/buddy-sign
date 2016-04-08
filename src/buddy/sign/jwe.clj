;; Copyright (c) 2014-2016 Andrey Antukh <niwi@niwi.nz>
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

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40
;; - http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
;; - http://tools.ietf.org/html/rfc3394 (AES Key Wrap Algorithm)
;; - http://tools.ietf.org/html/rfc3447 (RSA OAEP)

(ns buddy.sign.jwe
  "Json Web Encryption."
  (:require [clojure.string :as str]
            [cheshire.core :as json]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.crypto :as crypto]
            [buddy.core.padding :as padding]
            [buddy.core.keys :as keys]
            [buddy.util.deflate :as deflate]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwe.cek :as cek]
            [buddy.sign.util :as util])
  (:import org.bouncycastle.crypto.InvalidCipherTextException
           java.nio.ByteBuffer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- encode-header
  [{:keys [alg typ enc zip]}]
  (let [alg (if (= alg :dir) "dir" (str/upper-case (name alg)))
        typ (.toUpperCase (name typ))
        enc (.toUpperCase (name enc))
        header (merge {:alg alg :typ typ :enc enc}
                      (when zip {:zip "DEF"}))]
    ;; (-> (codecs/str->safebase64 "{\"enc\":\"A128GCM\",\"alg\":\"dir\"}")
    ;;     (codecs/str->bytes))
    (b64/encode (json/generate-string header))))

(defn- parse-header
  [^String headerdata {:keys [alg enc] :or {alg :dir enc :a128cbc-hs256}}]
  (let [header (-> (b64/decode headerdata)
                   (codecs/bytes->str)
                   (json/parse-string true))]
    (when (not= alg (keyword (str/lower-case (:alg header))))
      (throw (ex-info "The `alg` param mismatch with header value."
                      {:type :validation :cause :header})))
    (when (not= enc (keyword (str/lower-case (:enc header))))
      (throw (ex-info "The `enc` param mismatch with header value."
                      {:type :validation :cause :header})))

    {:alg alg
     :enc enc
     :zip (= (:zip header) "DEF")}))

(defmulti generate-iv :enc)
(defmethod generate-iv :a128cbc-hs256 [_] (nonce/random-bytes 16))
(defmethod generate-iv :a192cbc-hs384 [_] (nonce/random-bytes 16))
(defmethod generate-iv :a256cbc-hs512 [_] (nonce/random-bytes 16))
(defmethod generate-iv :a128gcm [_] (nonce/random-bytes 12))
(defmethod generate-iv :a192gcm [_] (nonce/random-bytes 12))
(defmethod generate-iv :a256gcm [_] (nonce/random-bytes 12))

(defn- encode-claims
  [claims zip opts]
  (let [additional (-> (select-keys opts [:exp :nbf :iat :iss :aud])
                       (jws/normalize-nil-claims)
                       (jws/normalize-date-claims))
        data (-> (jws/normalize-date-claims claims)
                 (merge additional)
                 (json/generate-string)
                 (codecs/to-bytes))]
    (if zip
      (deflate/compress data)
      data)))


;; TODO: split validation from parsing

(defn- parse-claims
  [^bytes claimsdata zip {:keys [max-age iss aud]}]
  (let [claims (-> (if zip (deflate/uncompress claimsdata) claimsdata)
                   (codecs/bytes->str)
                   (json/parse-string true))
        now (util/timestamp)]
    (when (and iss (not= iss (:iss claims)))
      (throw (ex-info (str "Issuer does not match " iss)
                      {:type :validation :cause :iss})))
    (when (and aud (not= aud (:aud claims)))
      (throw (ex-info (str "Audience does not match " aud)
                      {:type :validation :cause :aud})))
    (when (and (:exp claims) (> now (:exp claims)))
      (throw (ex-info (format "Token is older than :exp (%s)" (:exp claims))
                      {:type :validation :cause :exp})))
    (when (and (:nbf claims) (> now (:nbf claims)))
      (throw (ex-info (format "Token is older than :nbf (%s)" (:nbf claims))
                      {:type :validation :cause :nbf})))
    (when (and (:iat claims) (number? max-age) (> (- now (:iat claims)) max-age))
      (throw (ex-info (format "Token is older than max-age (%s)" max-age)
                      {:type :validation :cause :max-age})))
    claims))

(defmulti aead-encrypt :alg)
(defmulti aead-decrypt :alg)

(defmethod aead-encrypt :a128cbc-hs256
  [{:keys [alg plaintext secret iv aad] :as params}]
  (let [result (crypto/-encrypt {:alg :aes128-cbc-hmac-sha256 :input plaintext
                                 :key secret :iv iv :aad aad})
        resultlen (count result)
        ciphertext (bytes/slice result 0 (- resultlen 16))
        tag (bytes/slice result (- resultlen 16) resultlen)]
    [ciphertext tag]))

(defmethod aead-decrypt :a128cbc-hs256
  [{:keys [alg authtag ciphertext secret iv aad] :as params}]
  (crypto/-decrypt {:alg :aes128-cbc-hmac-sha256
                    :input (bytes/concat ciphertext authtag)
                    :key secret
                    :iv iv
                    :aad aad}))

(defmethod aead-encrypt :a192cbc-hs384
  [{:keys [alg plaintext secret iv aad] :as params}]
  (let [result (crypto/-encrypt {:alg :aes192-cbc-hmac-sha384 :input plaintext
                                 :key secret :iv iv :aad aad})
        resultlen (count result)
        ciphertext (bytes/slice result 0 (- resultlen 24))
        tag (bytes/slice result (- resultlen 24) resultlen)]
    [ciphertext tag]))

(defmethod aead-decrypt :a192cbc-hs384
  [{:keys [alg authtag ciphertext secret iv aad] :as params}]
  (crypto/-decrypt {:alg :aes192-cbc-hmac-sha384
                    :input (bytes/concat ciphertext authtag)
                    :key secret
                    :iv iv
                    :aad aad}))

(defmethod aead-encrypt :a256cbc-hs512
  [{:keys [alg plaintext secret iv aad] :as params}]
  (let [result (crypto/-encrypt {:alg :aes256-cbc-hmac-sha512 :input plaintext
                                 :key secret :iv iv :aad aad})
        resultlen (count result)
        ciphertext (bytes/slice result 0 (- resultlen 32))
        tag (bytes/slice result (- resultlen 32) resultlen)]
    [ciphertext tag]))

(defmethod aead-decrypt :a256cbc-hs512
  [{:keys [alg authtag ciphertext secret iv aad] :as params}]
  (crypto/-decrypt {:alg :aes256-cbc-hmac-sha512
                    :input (bytes/concat ciphertext authtag)
                    :key secret
                    :iv iv
                    :aad aad}))

(defmethod aead-encrypt :a128gcm
  [{:keys [alg plaintext secret iv aad] :as params}]
  (let [result (crypto/-encrypt {:alg :aes128-gcm
                                 :input plaintext
                                 :key secret
                                 :iv iv
                                 :aad aad})
        resultlen (alength result)
        ciphertext (bytes/slice result 0 (- resultlen 16))
        tag (bytes/slice result (- resultlen 16) resultlen)]
    [ciphertext tag]))

(defmethod aead-decrypt :a128gcm
  [{:keys [alg authtag ciphertext secret iv aad] :as params}]
  (crypto/-decrypt {:alg :aes128-gcm
                    :input (bytes/concat ciphertext authtag)
                    :key secret
                    :iv iv
                    :aad aad}))

(defmethod aead-encrypt :a192gcm
  [{:keys [alg plaintext secret iv aad] :as params}]
  (let [result (crypto/-encrypt {:alg :aes192-gcm :input plaintext
                                 :key secret :iv iv :aad aad})
        resultlen (count result)
        ciphertext (bytes/slice result 0 (- resultlen 16))
        tag (bytes/slice result (- resultlen 16) resultlen)]
    [ciphertext tag]))

(defmethod aead-decrypt :a192gcm
  [{:keys [alg authtag ciphertext secret iv aad] :as params}]
  (crypto/-decrypt {:alg :aes192-gcm
                    :input (bytes/concat ciphertext authtag)
                    :key secret
                    :iv iv
                    :aad aad}))

(defmethod aead-encrypt :a256gcm
  [{:keys [alg plaintext secret iv aad] :as params}]
  (let [result (crypto/-encrypt {:alg :aes256-gcm :input plaintext
                                 :key secret :iv iv :aad aad})
        resultlen (count result)
        ciphertext (bytes/slice result 0 (- resultlen 16))
        tag (bytes/slice result (- resultlen 16) resultlen)]
    [ciphertext tag]))

(defmethod aead-decrypt :a256gcm
  [{:keys [alg authtag ciphertext secret iv aad] :as params}]
  (crypto/-decrypt {:alg :aes256-gcm
                    :input (bytes/concat ciphertext authtag)
                    :key secret
                    :iv iv
                    :aad aad}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:private bytes->base64str
  (comp codecs/bytes->str #(b64/encode % true)))

(defn encrypt
  "Encrypt then sign arbitrary length string/byte array using
  json web encryption."
  [claims key & [{:keys [alg enc exp nbf iat zip typ iv]
                  :or {alg :dir enc :a128cbc-hs256 zip false typ :jws}
                  :as opts}]]
  {:pre [(map? claims)]}
  (let [scek (cek/generate {:key key :alg alg :enc enc})
        ecek (cek/encrypt {:key key :cek scek :alg alg :enc enc})
        iv (generate-iv {:enc enc})
        header (encode-header {:alg alg :enc enc :zip zip :typ typ})
        claims (encode-claims claims zip opts)
        [ciphertext authtag] (aead-encrypt {:alg enc
                                            :plaintext claims
                                            :secret scek
                                            :aad header
                                            :iv iv})]
    (str/join "." [(codecs/bytes->str header)
                   (bytes->base64str ecek)
                   (bytes->base64str iv)
                   (bytes->base64str ciphertext)
                   (bytes->base64str authtag)])))

(defn decrypt
  "Decrypt the jwe compliant message and return its claims."
  ([input key] (decrypt input key {}))
  ([input key opts]
   (try
     (let [[header ecek iv ciphertext authtag] (str/split input #"\." 5)
           {:keys [alg enc zip]} (parse-header header opts)
           ecek (b64/decode ecek)
           scek (cek/decrypt {:key key :ecek ecek :alg alg :enc enc})
           iv (b64/decode iv)
           header (codecs/str->bytes header)
           ciphertext (b64/decode ciphertext)
           authtag (b64/decode authtag)
           claims (aead-decrypt {:ciphertext ciphertext
                                 :authtag authtag
                                 :alg enc
                                 :aad header
                                 :secret scek
                                 :iv iv})]
       (parse-claims claims zip opts))
     (catch com.fasterxml.jackson.core.JsonParseException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature})))
     (catch org.bouncycastle.crypto.InvalidCipherTextException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature}))))))

(util/defalias encode encrypt)
(util/defalias decode decrypt)
