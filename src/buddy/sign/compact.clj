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
            [buddy.core.mac :as mac]
            [buddy.core.dsa :as dsa]
            [buddy.core.nonce :as nonce]
            [buddy.sign.jws :as jws]
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [taoensso.nippy :as nippy]
            [taoensso.nippy.compression :as nippycompress])
  (:import clojure.lang.Keyword))

(defn- sign-poly
  [input options]
  (let [iv (or (:iv options)
               (nonce/random-bytes 16))]
    (-> (mac/hash input (assoc options :iv iv))
        (bytes/concat iv))))

(defn- verify-poly
  [input signature options]
  (let [iv (bytes/slice signature 16 (count signature))
        signature' (bytes/slice signature 0 16)]
    (mac/verify input signature' (assoc options :iv iv))))

(def ^{:doc "List of supported signing algorithms"
       :dynamic true}
  *signers-map*
  {:hs256 {:signer   #(mac/hash %1 {:alg :hmac+sha256 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha256 :key %3})}
   :hs512 {:signer   #(mac/hash %1 {:alg :hmac+sha512 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha512 :key %3})}
   :rs256 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha256 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha256 :key %3})}
   :rs512 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha512 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha512 :key %3})}
   :ps256 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha256 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha256 :key %3})}
   :ps512 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha512 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha512 :key %3})}
   :es256 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha256 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha256 :key %3 })}
   :es512 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha512 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha512 :key %3})}
   :poly1305-aes {:signer   #(sign-poly %1 {:alg :poly1305+aes :key %2})
                  :verifier #(verify-poly %1 %2 {:alg :poly1305+aes :key %3})}
   :poly1305-serpent {:signer   #(sign-poly %1 {:alg :poly1305+serpent :key %2})
                      :verifier #(verify-poly %1 %2 {:alg :poly1305+serpent :key %3})}
   :poly1305-twofish {:signer   #(sign-poly %1 {:alg :poly1305+twofish :key %2})
                      :verifier #(verify-poly %1 %2 {:alg :poly1305+twofish :key %3})}})

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

(defn sign
  "Sign arbitrary length string/byte array using
  compact sigining method."
  [data key & [{:keys [alg compress]
                :or {alg :hs256 compress true}}]]
  (let [input (serialize data compress)
        salt (nonce/random-nonce 8)
        stamp (codecs/long->bytes (util/timestamp))
        signature (-> (bytes/concat input salt stamp)
                      (calculate-signature key alg))]
    (str/join "." [(codecs/bytes->safebase64 input)
                   (codecs/bytes->safebase64 signature)
                   (codecs/bytes->safebase64 salt)
                   (codecs/bytes->safebase64 stamp)])))

(defn unsign
  "Given a signed message, verify it and return
  the decoded data."
  [data key & [{:keys [alg compress max-age]
                :or {alg :hs256 compress true}}]]
  (let [[input signature salt stamp] (str/split data #"\." 4)
        input (codecs/safebase64->bytes input)
        signature (codecs/safebase64->bytes signature)
        salt (codecs/safebase64->bytes salt)
        stamp (codecs/safebase64->bytes stamp)
        candidate (bytes/concat input salt stamp)]
    (when-not (verify-signature candidate signature key alg)
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :signature})))
    (let [now (util/timestamp)
          stamp (codecs/bytes->long stamp)]
      (when (and (number? max-age) (> (- now stamp) max-age))
        (throw (ex-info (format "Token is older than %s" max-age)
                        {:type :validation :cause :max-age})))
      (nippy/thaw input {:v1-compatibility? false}))))

(util/defalias encode sign)
(util/defalias decode unsign)
