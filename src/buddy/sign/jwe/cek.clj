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

(ns buddy.sign.jwe.cek
  "Json Web Encryption Content Encryption Key utilities."
  (:require [clojure.core.match :refer [match]]
            [buddy.core.codecs :as codecs]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation: Content Encryption Keys
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- validate-keylength-for-algorithm
  [key algorithn]
  (let [keylength (count key)]
    (case algorithn
      :dir true
      :a128kw (= keylength 16)
      :a192kw (= keylength 24)
      :a256kw (= keylength 32))))

(defn generate
  [{:keys [key alg enc] :as options}]
  (match [alg enc]
    [:dir _] (codecs/->byte-array key)
    [(:or :a128kw :a192kw :a256kw) :a128cbc-hs256] (nonce/random-bytes 32)
    [(:or :a128kw :a192kw :a256kw) :a192cbc-hs384] (nonce/random-bytes 48)
    [(:or :a128kw :a192kw :a256kw) :a256cbc-hs512] (nonce/random-bytes 64)
    [(:or :a128kw :a192kw :a256kw) :a128gcm] (nonce/random-bytes 16)
    [(:or :a128kw :a192kw :a256kw) :a192gcm] (nonce/random-bytes 24)
    [(:or :a128kw :a192kw :a256kw) :a256gcm] (nonce/random-bytes 32)))

(defn encrypt
  [{:keys [key alg enc cek] :as options}]
  {:pre [(validate-keylength-for-algorithm key alg)]}
  (let [secret (codecs/->byte-array key)]
    (match [alg]
      [:dir] (byte-array 0)
      [(:or :a128kw :a192kw :a256kw)] (keys/wrap cek secret :aes))))

(defn decrypt
  [{:keys [key alg enc ecek] :as options}]
  (let [secret (codecs/->byte-array key)]
    (match [alg]
      [:dir] (codecs/->byte-array key)
      [(:or :a128kw :a192kw :a256kw)] (keys/unwrap ecek secret :aes))))
