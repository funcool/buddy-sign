;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.sign.jwt
  (:require [buddy.sign.jws :as jws]
            [buddy.sign.util :as util]))

(defn validate-claims [claims {:keys [max-age iss aud now] :or
                               {now (util/timestamp)}}]
  (when (and iss (not= iss (:iss claims)))
    (throw (ex-info (str "Issuer does not match " iss)
                    {:type :validation :cause :iss})))
  (when (and aud (not= aud (:aud claims)))
    (throw (ex-info (str "Audience does not match " aud)
                    {:type :validation :cause :aud})))
  (when (and (:exp claims) (>= now (:exp claims)))
    (throw (ex-info (format "Token is expired (%s)" (:exp claims))
                    {:type :validation :cause :exp})))
  (when (and (:nbf claims) (< now (:nbf claims)))
    (throw (ex-info (format "Token is not yet valid (%s)" (:nbf claims))
                    {:type :validation :cause :nbf})))
  (when (and (:iat claims) (< now (:iat claims)))
    (throw (ex-info (format "Token is from the future (%s)" (:iat claims))
                    {:type :validation :cause :iat})))
  (when (and (:iat claims) (number? max-age) (> (- now (:iat claims)) max-age))
    (throw (ex-info (format "Token is older than max-age (%s)" max-age)
                    {:type :validation :cause :max-age})))
  claims)

(defn get-claims-jws
  ([message pkey] (get-claims-jws message pkey {}))
  ([message pkey opts]
   (-> (jws/unsign message pkey opts)
       (validate-claims opts))))

