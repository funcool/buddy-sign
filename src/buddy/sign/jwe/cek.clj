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

(ns buddy.sign.jwe.cek
  "Json Web Encryption Content Encryption Key utilities."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys])
  (:import javax.crypto.Cipher
           java.security.SecureRandom))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation: Content Encryption Keys
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- validate-keylength-for-algorithm
  [key algorithn]
  (case algorithn
    :dir true
    :rsa-oaep true
    :rsa-oaep-256 true
    :rsa1_5 true
    :a128kw (= (count key) 16)
    :a192kw (= (count key) 24)
    :a256kw (= (count key) 32)))

(defn- encrypt-with-rsaaoep
  [cek pubkey]
  (let [cipher (Cipher/getInstance "RSA/ECB/OAEPWithSHA-1AndMGF1Padding" "BC")
        sr (SecureRandom.)]
    (.init cipher Cipher/ENCRYPT_MODE pubkey sr)
    (.doFinal cipher cek)))

(defn- decrypt-with-rsaaoep
  [ecek privkey]
  (let [cipher (Cipher/getInstance "RSA/ECB/OAEPWithSHA-1AndMGF1Padding" "BC")
        sr (SecureRandom.)]
    (.init cipher Cipher/DECRYPT_MODE privkey  sr)
    (.doFinal cipher ecek)))

(defn- encrypt-with-rsaaoep-sha256
  [cek pubkey]
  (let [cipher (Cipher/getInstance "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" "BC")
        sr (SecureRandom.)]
    (.init cipher Cipher/ENCRYPT_MODE pubkey sr)
    (.doFinal cipher cek)))

(defn- decrypt-with-rsaaoep-sha256
  [ecek privkey]
  (let [cipher (Cipher/getInstance "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" "BC")
        sr (SecureRandom.)]
    (.init cipher Cipher/DECRYPT_MODE privkey  sr)
    (.doFinal cipher ecek)))

(defn- encrypt-with-rsa-pkcs15
  [cek pubkey]
  (let [cipher (Cipher/getInstance "RSA/ECB/PKCS1Padding" "BC")
        sr (SecureRandom.)]
    (.init cipher Cipher/ENCRYPT_MODE pubkey sr)
    (.doFinal cipher cek)))

(defn- decrypt-with-rsa-pkcs15
  [ecek privkey]
  (let [cipher (Cipher/getInstance "RSA/ECB/PKCS1Padding" "BC")
        sr (SecureRandom.)]
    (.init cipher Cipher/DECRYPT_MODE privkey  sr)
    (.doFinal cipher ecek)))

(def ^:private
  aeskw? #{:a128kw :a192kw :a256kw})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn generate
  [{:keys [key alg enc] :as options}]
  (case alg
    :dir (codecs/to-bytes key)
    (case enc
      :a128cbc-hs256 (nonce/random-bytes 32)
      :a192cbc-hs384 (nonce/random-bytes 48)
      :a256cbc-hs512 (nonce/random-bytes 64)
      :a128gcm (nonce/random-bytes 16)
      :a192gcm (nonce/random-bytes 24)
      :a256gcm (nonce/random-bytes 32))))

(defn encrypt
  [{:keys [key alg enc cek] :as options}]
  {:pre [(validate-keylength-for-algorithm key alg)]}
  (cond
    (= alg :dir)
    (byte-array 0)

    (= alg :rsa-oaep)
    (encrypt-with-rsaaoep cek key)

    (= alg :rsa-oaep-256)
    (encrypt-with-rsaaoep-sha256 cek key)

    (= alg :rsa1_5)
    (encrypt-with-rsa-pkcs15 cek key)

    (aeskw? alg)
    (let [secret (codecs/to-bytes key)]
      (keys/wrap cek secret :aes))))

(defn decrypt
  [{:keys [key alg enc ecek] :as options}]
  (cond
    (= alg :dir)
    (codecs/to-bytes key)

    (= alg :rsa-oaep)
    (decrypt-with-rsaaoep ecek key)

    (= alg :rsa-oaep-256)
    (decrypt-with-rsaaoep-sha256 ecek key)

    (= alg :rsa1_5)
    (decrypt-with-rsa-pkcs15 ecek key)

    (aeskw? alg)
    (let [secret (codecs/to-bytes key)]
      (keys/unwrap ecek secret :aes))))
