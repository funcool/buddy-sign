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

(ns buddy.sign.jwt-tests
  (:require [clojure.test :refer :all]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]))

(def mac-secret "mac-secret")

(deftest jwt-jws-decode 
  (let [claims {:aud "buddy"}
        signed (jws/sign claims mac-secret {:alg :hs256 :typ "JWT"})
        returned-claims (jwt/get-claims-jws signed mac-secret {:alg :hs256})]
    (is (= returned-claims claims) "decoded claims must match up to original"))) 

