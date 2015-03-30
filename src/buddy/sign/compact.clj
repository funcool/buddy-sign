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

(ns buddy.sign.compact
  "Compact high level message signing implementation.

  It has high influence by django's cryptographic library
  and json web signature/encryption but with focus on have
  a compact representation. It's build on top of fantastic
  ptaoussanis/nippy serialization library.

  This singing implementation is not very efficient with
  small messages, but is very space efficient with big
  messages.

  The purpose of this implementation is for secure message
  transfer, it is not really good candidate for auth token
  because of not good space efficiency for small messages."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :as keys]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.mac.poly1305 :as poly]
            [buddy.core.sign.rsapss :as rsapss]
            [buddy.core.sign.rsapkcs15 :as rsapkcs]
            [buddy.core.sign.ecdsa :as ecdsa]
            [buddy.core.nonce :as nonce]
            [buddy.sign.jws :as jws]
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [taoensso.nippy :as nippy]
            [taoensso.nippy.compression :as nippycompress]
            [cats.monad.exception :as exc]
            [slingshot.slingshot :refer [throw+]])
  (:import clojure.lang.Keyword))

(def ^{:doc "List of supported signing algorithms"
       :dynamic true}
  *signers-map* {:hs256 {:signer   #(hmac/hash %1 %2 :sha256)
                         :verifier #(hmac/verify %1 %2 %3 :sha256)}
                 :hs512 {:signer   #(hmac/hash %1 %2 :sha512)
                         :verifier #(hmac/verify %1 %2 %3 :sha512)}
                 :rs256 {:signer   #(rsapkcs/sign %1 %2 :sha256)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha256)}
                 :rs512 {:signer   #(rsapkcs/sign %1 %2 :sha512)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha512)}
                 :ps256 {:signer   #(rsapss/sign %1 %2 :sha256)
                         :verifier #(rsapss/verify %1 %2 %3 :sha256)}
                 :ps512 {:signer   #(rsapss/sign %1 %2 :sha512)
                         :verifier #(rsapss/verify %1 %2 %3 :sha512)}
                 :es256 {:signer   #(ecdsa/sign %1 %2 :sha256)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha256)}
                 :es512 {:signer   #(ecdsa/sign %1 %2 :sha512)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha512)}
                 :poly1305-aes {:signer #(poly/hash %1 %2 :aes)
                                :verifier #(poly/verify %1 %2 %3 :aes)}
                 :poly1305-serpent {:signer #(poly/hash %1 %2 :serpent)
                                    :verifier #(poly/verify %1 %2 %3 :serpent)}
                 :poly1305-twofish {:signer #(poly/hash %1 %2 :twofish)
                                    :verifier #(poly/verify %1 %2 %3 :twofish)}})

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array."
  [^bytes input ^bytes key ^Keyword alg]
  (let [signer (get-in *signers-map* [alg :signer])]
    (signer input key)))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not."
  [^bytes input ^bytes signature ^bytes key ^Keyword alg]
  (let [verifier (get-in *signers-map* [alg :verifier])]
    (verifier input signature key)))

(defn- serialize
  [data compress]
  (cond
    (true? compress)
    (nippy/freeze data {:compressor nippy/snappy-compressor})

    (satisfies? nippycompress/ICompressor compress)
    (nippy/freeze data {:compressor compress})

    :else
    (nippy/freeze data)))

(defn encode
  "Sign arbitrary length string/byte array using
  compact sigining method."
  [data key & [{:keys [alg compress]
                :or {alg :hs256 compress true}}]]
  (exc/try-on
   (let [input (serialize data compress)
         salt (nonce/random-nonce 8)
         stamp (codecs/long->bytes (util/timestamp))
         signature (-> (bytes/concat input salt stamp)
                       (calculate-signature key alg))]
     (str/join "." [(codecs/bytes->safebase64 input)
                    (codecs/bytes->safebase64 signature)
                    (codecs/bytes->safebase64 salt)
                    (codecs/bytes->safebase64 stamp)]))))

(defn decode
  "Given a signed message, verify it and return
  the decoded data.

  This function returns a monadic either instance,
  and if some error is happens in process of decoding
  and verification, it will be reported in an
  either/left instance."
  [data key & [{:keys [alg compress max-age]
                :or {alg :hs256 compress true}}]]
  (exc/try-on
   (let [[input signature salt stamp] (str/split data #"\." 4)
         input (codecs/safebase64->bytes input)
         signature (codecs/safebase64->bytes signature)
         salt (codecs/safebase64->bytes salt)
         stamp (codecs/safebase64->bytes stamp)
         candidate (bytes/concat input salt stamp)]
     (when-not (verify-signature candidate signature key alg)
       (throw+ {:type :validation :cause :auth :message "Message seems corrupt or manipulated."}))

     (let [now (util/timestamp)
           stamp (codecs/bytes->long stamp)]
       (when (and (number? max-age) (> (- now stamp) max-age))
         (throw+ {:type :validation :cause :max-age
                  :message (format "Token is older than max-age (%s)" max-age)}))
       (nippy/thaw input {:v1-compatibility? false})))))

(defn sign
  "Not monadic version of encode."
  [& args]
  (deref (apply encode args)))

(defn unsign
  "Not monadic version of decode."
  [& args]
  (deref (apply decode args)))
