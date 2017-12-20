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

(ns buddy.sign.jwk.proto
  (:require [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs])
  (:import (org.bouncycastle.util BigIntegers)))

;; it's actually pretty tricky to correctly calculate byte length
;; while converting BigInteger -> byte arrays, because BigInteger strips
;; leading zero bytes in constructor. This function works in my tests
;; but it can break with many leading zero bytes in keys
;; OTOH many leading zeros are sign of bad key so i think it's not critical
(defn calc-byte-length [^BigInteger bi]
  (int (Math/ceil (/ (.bitLength bi) 8.0))))

(defn b64str->bigint [string]
  (let [bs ^bytes (b64/decode string)]
    (BigIntegers/fromUnsignedByteArray bs)))

(defn bigint->b64str [length ^BigInteger bi]
  (-> (BigIntegers/asUnsignedByteArray length bi)
      (b64/encode true)
      (codecs/bytes->str)))

(defn bytes->b64str [^bytes bs]
  (-> bs
      (b64/encode true)
      (codecs/bytes->str)))

(defprotocol ConvertPublicJCA
  (public-key->jwk [public]))

(defprotocol ConvertPrivateJCA
  (private-key->jwk [private public]))

(defmulti jwk->private-key {:arglists '([jwk])} :kty)

(defmulti jwk->public-key {:arglists '([jwk])} :kty)

(defmulti thumbprint {:arglists '([jwk])} :kty)
