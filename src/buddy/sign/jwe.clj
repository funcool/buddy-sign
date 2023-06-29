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
  "Json Web Encryption"
  (:require
   [buddy.core.bytes :as bytes]
   [buddy.core.codecs :as bc]
   [buddy.core.codecs.base64 :as b64]
   [buddy.core.crypto :as crypto]
   [buddy.core.keys :as keys]
   [buddy.core.nonce :as nonce]
   [buddy.sign.jwe.cek :as cek]
   [buddy.sign.jws :as jws]
   [buddy.sign.util :as util]
   [buddy.util.deflate :as deflate]
   [cheshire.core :as json]
   [clojure.string :as str])
  (:import
   org.bouncycastle.crypto.InvalidCipherTextException))

;; --- Implementation details

(defn- generate-iv
  [{:keys [enc]}]
  (case enc
    :a128cbc-hs256 (nonce/random-bytes 16)
    :a192cbc-hs384 (nonce/random-bytes 16)
    :a256cbc-hs512 (nonce/random-bytes 16)
    :a128gcm (nonce/random-bytes 12)
    :a192gcm (nonce/random-bytes 12)
    :a256gcm (nonce/random-bytes 12)))

(defn- encode-payload
  [input zip]
  (cond-> (bc/to-bytes input)
    zip (deflate/compress)))

(defn- decode-payload
  [payload header]
  (let [{:keys [zip]} (util/parse-jose-header header)]
    (cond-> payload
      zip (deflate/uncompress payload))))

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
        resultlen  (alength ^bytes result)
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
  (let [result     (crypto/-encrypt {:alg :aes192-gcm
                                     :input plaintext
                                     :key secret
                                     :iv iv
                                     :aad aad})
        resultlen  (count result)
        ciphertext (bytes/slice result 0 (- resultlen 16))
        tag        (bytes/slice result (- resultlen 16) resultlen)]
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

;; --- Public Api

(def ^:private bytes->base64
  (comp bc/bytes->str #(bc/bytes->b64 % true)))

(defn decode-header
  "Given a message, decode the header.
  WARNING: This does not perform any signature validation"
  [input]
  (let [[header] (str/split input #"\." 2)]
    (util/parse-jose-header (bc/str->bytes header))))

(defn encrypt
  "Encrypt then sign arbitrary length string/byte array using
  json web encryption"
  ([payload key] (encrypt payload key nil))
  ([payload key {:keys [alg enc zip header]
                 :or {alg :dir enc :a128cbc-hs256 zip false}}]
   (let [scek    (cek/generate {:key key :alg alg :enc enc})
         ecek    (cek/encrypt {:key key :cek scek :alg alg :enc enc})
         iv      (generate-iv {:enc enc})
         header  (cond-> (into {:alg alg :enc enc} header)
                   zip (assoc :zip "DEF"))
         header  (util/encode-jose-header header)
         payload (encode-payload payload zip)

         [ciphertext authtag]
         (aead-encrypt {:alg enc
                        :plaintext payload
                        :secret scek
                        :aad header
                        :iv iv})]

     (str (bc/bytes->str header) "."
          (bytes->base64 ecek) "."
          (bytes->base64 iv) "."
          (bytes->base64 ciphertext) "."
          (bytes->base64 authtag)))))

(defn decrypt
  "Decrypt the jwe compliant message and return its payload"
  ([input key] (decrypt input key nil))
  ([input key {:keys [alg enc] :or {alg :dir enc :a128cbc-hs256} :as opts}]
   (let [[header ecek iv ciphertext authtag] (some-> input (str/split #"\." 5))]
     (when (or (nil? ecek) (nil? iv) (nil? ciphertext) (nil? authtag))
       (throw (ex-info "Message seems corrupt or manipulated"
                       {:type :validation :cause :signature})))
     (try
       (let [ecek    (-> ecek
                         (bc/str->bytes)
                         (bc/b64->bytes true))
             iv      (-> iv
                         (bc/str->bytes)
                         (bc/b64->bytes true))
             ctxt    (-> ciphertext
                         (bc/str->bytes)
                         (bc/b64->bytes true))
             authtag (-> authtag
                         (bc/str->bytes)
                         (bc/b64->bytes true))

             header  (bc/str->bytes header)

             scek    (cek/decrypt {:key key :ecek ecek :alg alg :enc enc})

             payload (aead-decrypt {:ciphertext ctxt
                                    :authtag authtag
                                    :alg enc
                                    :aad header
                                    :secret scek
                                    :iv iv})]
         (decode-payload payload header))

       (catch java.lang.IllegalArgumentException e
         (throw (ex-info "Message seems corrupt or manipulated"
                         {:type :validation :cause :token}
                         e)))
       (catch java.lang.AssertionError e
         (throw (ex-info "Message seems corrupt or manipulated"
                         {:type :validation :cause :token}
                         e)))
       (catch com.fasterxml.jackson.core.JsonParseException e
         (throw (ex-info "Message seems corrupt or manipulated"
                         {:type :validation :cause :signature}
                         e)))
       (catch org.bouncycastle.crypto.InvalidCipherTextException e
         (throw (ex-info "Message seems corrupt or manipulated"
                         {:type :validation :cause :signature}
                         e)))))))

(util/defalias encode encrypt)
(util/defalias decode decrypt)
