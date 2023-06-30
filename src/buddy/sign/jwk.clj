;; Copyright (c) Andrey Antukh <niwi@niwi.nz>
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
  "A JWK key reading functions"
  (:require
   [cheshire.core :as json]
   [buddy.core.keys :as bk]))

(defn public-key
  "Creates a PublicKey instance from JWK. This function
  accepts JSON formatted string or a clojure map."
  [input]
  (let [input (cond
                (string? input) (json/parse-string input true)
                (map? input)    input
                :else           (throw (IllegalArgumentException. "expected json string or map")))]
    (bk/jwk->public-key input)))

(defn private-key
  "Creates a PublicKey instance from JWK. This function
  accepts JSON formatted string or a clojure map."
  [input]
  (let [input (cond
                (string? input) (json/parse-string input true)
                (map? input)    input
                :else           (throw (IllegalArgumentException. "expected json string or map")))]
    (bk/jwk->private-key input)))

(defn thumbprint
  [input]
  (let [input (cond
                (string? input) (json/parse-string input true)
                (map? input)    input
                :else           (throw (IllegalArgumentException. "expected json string or map")))]
    (bk/jwk-thumbprint input)))
