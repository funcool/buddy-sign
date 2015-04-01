;; Copyright (c) 2014-2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.sign.jwe
  "Json Web Encryption."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.crypto :as crypto]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.padding :as padding]
            [buddy.sign.jws :as jws]
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [cheshire.core :as json]
            [cats.core :as m]
            [cats.monad.exception :as exc]
            [slingshot.slingshot :refer [throw+ try+]])
  (:import clojure.lang.Keyword
           org.bouncycastle.crypto.InvalidCipherTextException
           java.nio.ByteBuffer
           java.io.ByteArrayInputStream
           java.io.ByteArrayOutputStream
           java.util.zip.Deflater
           java.util.zip.DeflaterOutputStream
           java.util.zip.InflaterInputStream
           java.util.zip.Inflater))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Compression primitives
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn compress-bytes
  [^bytes input]
  (let [out (ByteArrayOutputStream.)
        def (Deflater. Deflater/DEFLATED true)
        dout (DeflaterOutputStream. out def)]
    (.write dout input)
    (.close dout)
    (.toByteArray out)))

(defn uncompress-bytes
  [^bytes input]
  (let [input (ByteArrayInputStream. bytes)
        inflater (Inflater. true)
        infout (InflaterInputStream. input inflater)
        output (ByteArrayOutputStream.)
        buffer (byte-array 1024)]
    (loop []
      (let [readed (.read infout buffer)]
        (when (pos? readed)
          (.write output buffer 0 readed)
          (recur))))
    (.close infout)
    (.close output)
    (.toByteArray output)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Crypto primitives/helpers.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- split-by-blocksize
  "Split a byte array in blocksize blocks.
  Given a arbitrary size bytearray and block size in bytes,
  returns a lazy sequence of bytearray blocks of blocksize
  size. If last block does not have enought data for fill
  all block, it is padded using zerobyte padding."
  ([^bytes input ^long blocksize]
   (split-by-blocksize input blocksize true))
  ([^bytes input ^long blocksize additional]
   (let [inputsize (count input)]
     (loop [cursormin 0
            cursormax blocksize
            remain inputsize
            result []]
       (cond
         (= remain 0)
         (if additional
           (conj result (byte-array blocksize))
           result)

         (< remain blocksize)
         (let [buffer (byte-array blocksize)]
           (System/arraycopy input cursormin buffer 0 remain)
           (conj result buffer))

         (>= remain blocksize)
         (let [buffer (byte-array blocksize)]
           (System/arraycopy input cursormin buffer 0 blocksize)
           (recur cursormax
                  (+ cursormax blocksize)
                  (- inputsize cursormax)
                  (conj result buffer))))))))

(defn- encrypt-cbc
  [cipher input key iv]
  (let [blocksize (crypto/get-block-size cipher)
        blocks (split-by-blocksize input blocksize)]
    (crypto/initialize! cipher {:op :encrypt :iv iv :key key})
    (apply bytes/concat
           (reduce (fn [acc block]
                     (let [padnum (padding/count block :zerobyte)
                           length (count block)]
                       (when (> padnum 0)
                         (padding/pad! block (- length padnum) :pkcs7))
                       (let [eblock (crypto/process-block! cipher block)]
                         (conj acc eblock))))
                   [] blocks))))

(defn- decrypt-cbc
  [cipher input key iv]
  (let [blocksize (crypto/get-block-size cipher)
        blocks (split-by-blocksize input blocksize false)]
    (crypto/initialize! cipher {:op :decrypt :iv iv :key key})
    (apply bytes/concat
           (reduce (fn [acc block]
                     (let [block (crypto/process-block! cipher block)]
                       (when (padding/padded? block :pkcs7)
                         (padding/unpad! block :pkcs7))
                       (conj acc block)))
                   [] blocks))))

(defn- encrypt-gcm
  [input key iv aad]
  (let [cipher (crypto/block-cipher :aes :gcm)]
    (crypto/initialize! cipher {:iv iv :key key :tagsize 128 :op :encrypt :aad aad})
    (let [outputlength (crypto/get-output-size cipher (count input))
          output (byte-array outputlength)
          offset (crypto/process-block! cipher input 0 output 0)]
      (try+
        (crypto/calculate-authtag! cipher output offset)
        (catch InvalidCipherTextException e
          (let [message (str "Couldn't generate gcm authentication tag: " (.getMessage e))]
            (throw+ {:type :encryption :cause :authtag :message message} e))))
      (let [ciphertextlength (- outputlength 16)
            ciphertext (byte-array ciphertextlength)
            authtag (byte-array 16)]
        (System/arraycopy output 0 ciphertext 0 ciphertextlength)
        (System/arraycopy output ciphertextlength, authtag 0 16)
        [ciphertext authtag]))))

(defn- decrypt-gcm
  [ciphertext authtag key iv aad]
  (let [cipher (crypto/block-cipher :aes :gcm)
        inputlength (+ (count ciphertext) (count authtag))
        input (byte-array inputlength)]
    (crypto/initialize! cipher {:iv iv :key key :tagsize 128 :op :decrypt :aad aad})
    (System/arraycopy ciphertext 0 input 0 (count ciphertext))
    (System/arraycopy authtag 0 input (count ciphertext) (count authtag))
    (let [outputlength (crypto/get-output-size cipher inputlength)
          output (byte-array outputlength)
          offset (crypto/process-block! cipher input 0 output 0)]
      (try+
        (crypto/calculate-authtag! cipher output offset)
        (catch InvalidCipherTextException e
          (let [message (str "Couldn't validate gcm authentication tag: " (.getMessage e))]
            (throw+ {:type :encryption :cause :authtag :message message} e))))
      output)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def keylength? #(= (count %1) %2))
(def ivlength? #(= (count %1) %2))

(defmulti generate-cek :alg)
(defmethod generate-cek :dir
  [{:keys [key]}]
  (codecs/->byte-array key))

(defmulti encrypt-cek :alg)
(defmethod encrypt-cek :dir
  [{:keys [alg cek]}]
  (byte-array 0))

(defn generate-header
  [{:keys [alg enc zip]}]
  (let [data (merge {:alg (condp = alg
                            :dir "dir"
                            (str/upper-case (name alg)))
                     :enc (str/upper-case (name enc))}
                    (when (not= zip ::none)
                      {:zip (str/upper-case (name enc))}))]
    (-> (json/generate-string data)
        (codecs/str->bytes))))

(defn- parse-header
  [^String header]
  (let [header (codecs/safebase64->str header)
        {:keys [alg enc zip] :as header} (json/parse-string header true)]
    (when (or (nil? alg) (nil? enc))
      (throw+ {:type :parse :cause :header :message "Missing `alg` or `enc` key in header."}))
    (merge {:alg (keyword (str/lower-case alg))
            :enc (keyword (str/lower-case enc))}
           (when zip
             {:zip (keyword (str/lower-case zip))})
           (dissoc header :alg :enc :zip))))

(defmulti generate-iv :enc)
(defmethod generate-iv :a128cbc-hs256 [_] (nonce/random-bytes 16))
(defmethod generate-iv :a192cbc-hs384 [_] (nonce/random-bytes 16))
(defmethod generate-iv :a256cbc-hs512 [_] (nonce/random-bytes 16))
(defmethod generate-iv :a128gcm [_] (nonce/random-bytes 12))
(defmethod generate-iv :a192gcm [_] (nonce/random-bytes 12))
(defmethod generate-iv :a256gcm [_] (nonce/random-bytes 12))

(defn calculate-aad-length
  [aad]
  (let [length (* (count aad) 8)
        buffer (ByteBuffer/allocate 8)]
    (.putLong buffer length)
    (.array buffer)))

(defn extract-encryption-key
  [secret algorithm]
  {:pre [(bytes/bytes? secret)]}
  (case algorithm
    :a128cbc-hs256 (bytes/slice secret 16 32)
    :a192cbc-hs384 (bytes/slice secret 24 48)
    :a256cbc-hs512 (bytes/slice secret 32 64)))

(defn extract-authentication-key
  [secret algorithm]
  {:pre [(bytes/bytes? secret)]}
  (case algorithm
    :a128cbc-hs256 (bytes/slice secret 0 16)
    :a192cbc-hs384 (bytes/slice secret 0 24)
    :a256cbc-hs512 (bytes/slice secret 0 32)))

(defn- generate-authtag
  [{:keys [algorithm ciphertext authkey iv aad]}]
  (let [al (calculate-aad-length aad)
        data (bytes/concat aad iv ciphertext al)
        fulltag (hmac/hash data authkey algorithm)
        truncatesize (quot (count fulltag) 2)]
    (bytes/slice fulltag 0 truncatesize)))

(defn- verify-authtag
  [tag params]
  (let [tag' (generate-authtag params)]
    (bytes/equals? tag tag')))

(defmulti aead-encrypt :algorithm)

(defmethod aead-encrypt :a128cbc-hs256
  [{:keys [algorithm plaintext secret iv aad] :as params}]
  {:pre [(keylength? secret 32)
         (ivlength? iv 16)]}
  (let [cipher (crypto/block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key secret algorithm)
        authkey (extract-authentication-key secret algorithm)
        ciphertext (encrypt-cbc cipher plaintext encryptionkey iv)
        tag (generate-authtag {:algorithm :sha256
                               :ciphertext ciphertext
                               :authkey authkey
                               :aad aad
                               :iv iv})]
    [ciphertext tag]))

(defmethod aead-encrypt :a192cbc-hs384
  [{:keys [algorithm plaintext secret iv aad] :as params}]
  {:pre [(keylength? secret 48)
         (ivlength? iv 16)]}
  (let [cipher (crypto/block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key secret algorithm)
        authkey (extract-authentication-key secret algorithm)
        ciphertext (encrypt-cbc cipher plaintext encryptionkey iv)
        tag (generate-authtag {:algorithm :sha384
                               :ciphertext ciphertext
                               :authkey authkey
                               :aad aad
                               :iv iv})]
    [ciphertext tag]))

(defmethod aead-encrypt :a256cbc-hs512
  [{:keys [algorithm plaintext secret iv aad] :as params}]
  {:pre [(keylength? secret 64)
         (ivlength? iv 16)]}
  (let [cipher (crypto/block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key secret algorithm)
        authkey (extract-authentication-key secret algorithm)
        ciphertext (encrypt-cbc cipher plaintext encryptionkey iv)
        tag (generate-authtag {:algorithm :sha512
                               :ciphertext ciphertext
                               :authkey authkey
                               :aad aad
                               :iv iv})]
    [ciphertext tag]))

(defmethod aead-encrypt :a128gcm
  [{:keys [algorithm plaintext secret iv aad] :as params}]
  {:pre [(keylength? secret 16) (ivlength? iv 12)]}
  (encrypt-gcm plaintext secret iv aad))

(defmethod aead-encrypt :a192gcm
  [{:keys [algorithm plaintext secret iv aad] :as params}]
  {:pre [(keylength? secret 24) (ivlength? iv 12)]}
  (encrypt-gcm plaintext secret iv aad))

(defmethod aead-encrypt :a256gcm
  [{:keys [algorithm plaintext secret iv aad] :as params}]
  {:pre [(keylength? secret 32) (ivlength? iv 12)]}
  (encrypt-gcm plaintext secret iv aad))

(defmulti aead-decrypt :algorithm)

(defmethod aead-decrypt :a128cbc-hs256
  [{:keys [algorithm authtag ciphertext secret iv] :as params}]
  {:pre [(keylength? secret 32)
         (ivlength? iv 16)]}
  (let [cipher (crypto/block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key secret algorithm)
        authkey (extract-authentication-key secret algorithm)]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :algorithm :sha256))
      (throw+ {:type :validation :cause :authtag :message "Message seems corrupt or manipulated."}))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod aead-decrypt :a192cbc-hs384
  [{:keys [algorithm authtag ciphertext secret iv] :as params}]
  {:pre [(keylength? secret 48)
         (ivlength? iv 16)]}
  (let [cipher (crypto/block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key secret algorithm)
        authkey (extract-authentication-key secret algorithm)]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :algorithm :sha384))
      (throw+ {:type :validation :cause :authtag :message "Message seems corrupt or manipulated."}))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod aead-decrypt :a256cbc-hs512
  [{:keys [algorithm authtag ciphertext secret iv] :as params}]
  {:pre [(keylength? secret 64)
         (ivlength? iv 16)]}
  (let [cipher (crypto/block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key secret algorithm)
        authkey (extract-authentication-key secret algorithm)]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :algorithm :sha512))
      (throw+ {:type :validation :cause :authtag :message "Message seems corrupt or manipulated."}))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod aead-decrypt :a128gcm
  [{:keys [algorithm authtag ciphertext secret iv aad] :as params}]
  {:pre [(keylength? secret 16) (ivlength? iv 12)]}
  (decrypt-gcm ciphertext authtag secret iv aad))

(defmethod aead-decrypt :a192gcm
  [{:keys [algorithm authtag ciphertext secret iv aad] :as params}]
  {:pre [(keylength? secret 24) (ivlength? iv 12)]}
  (decrypt-gcm ciphertext authtag secret iv aad))

(defmethod aead-decrypt :a256gcm
  [{:keys [algorithm authtag ciphertext secret iv aad] :as params}]
  {:pre [(keylength? secret 32) (ivlength? iv 12)]}
  (decrypt-gcm ciphertext authtag secret iv aad))

(defn- generate-plaintext
  [claims zip exp nbf iat]
  (let [additionalclaims (-> (jws/normalize-nil-claims {:exp exp :nbf nbf :iat iat})
                             (jws/normalize-date-claims))
        data (-> (jws/normalize-date-claims claims)
                 (merge additionalclaims)
                 (json/generate-string)
                 (codecs/str->bytes))]
    (condp = zip
      ::none data
      :def (compress-bytes data))))

(defn- parse-plaintext
  [^bytes data zip]
  (let [data (condp = zip
               ::none data
               :def (uncompress-bytes data))]
    (-> (codecs/bytes->str data)
        (json/parse-string true))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encrypt
  "Encrypt then sign arbitrary length string/byte array using
  json web encryption."
  [claims key & [{:keys [alg enc exp nbf iat zip]
                  :or {alg :dir zip ::none
                       enc :a128cbc-hs256}
                  :as options}]]
  {:pre [(map? claims)]}
  (let [scek (generate-cek {:key key :alg alg})
        ecek (encrypt-cek {:cek scek :alg alg})
        iv (generate-iv {:enc enc})
        header (generate-header {:alg alg :enc enc :zip zip})
        plaintext (generate-plaintext claims zip exp nbf iat)
        [ciphertext authtag] (aead-encrypt {:algorithm enc
                                            :plaintext plaintext
                                            :secret scek
                                            :aad header
                                            :iv iv})]
    (str/join "." [(codecs/bytes->safebase64 header)
                   (codecs/bytes->safebase64 ecek)
                   (codecs/bytes->safebase64 iv)
                   (codecs/bytes->safebase64 ciphertext)
                   (codecs/bytes->safebase64 authtag)])))

(defn decrypt
  "Decrypt the jwe compliant message and return its claims."
  [input key & [{:keys [max-age]}]]
  (let [[header ecek iv ciphertext authtag] (str/split input #"\." 5)
        {:keys [alg enc zip] :or {zip ::none}} (parse-header header)
        ecek (codecs/safebase64->bytes ecek)
        scek (generate-cek {:key key :alg alg})
        iv (codecs/safebase64->bytes iv)
        header (codecs/safebase64->bytes header)
        ciphertext (codecs/safebase64->bytes ciphertext)
        authtag (codecs/safebase64->bytes authtag)
        plaintext (aead-decrypt {:ciphertext ciphertext
                                 :authtag authtag
                                 :algorithm enc
                                 :aad header
                                 :secret scek
                                 :iv iv})]
    (let [now (util/timestamp)
          claims (parse-plaintext plaintext zip)]
      (cond
        (and (:exp claims) (> now (:exp claims)))
        (throw+ {:type :validation
                 :cause :exp
                 :message (format "Token is older than :exp (%s)" (:exp claims))})

        (and (:nbf claims) (> now (:nbf claims)))
        (throw+ {:type :validation
                 :cause :nbf
                 :message (format "Token is older than :nbf (%s)" (:nbf claims))})

        (and (:iat claims) (number? max-age) (> (- now (:iat claims)) max-age))
        (throw+ {:type :validation
                 :cause :max-age
                 :message (format "Token is older than max-age (%s)" max-age)})

        :else claims))))

(defn encode
  "Encrypt then sign arbitrary length string/byte array using
  json web encryption and return the encrypted data wrapped in
  a Success type of Exception monad."
  [& args]
  (exc/try-on (apply encrypt args)))

(defn decode
  "Decrypt the jwe compliant message and return its claims wrapped
  in Success type of Exception monad."
  [& args]
  (exc/try-on (apply decrypt args)))
