;; Copyright (c) 2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.sign.util
  (:require [buddy.core.codecs :as codecs]
            [clj-time.coerce :as coerce]
            [clj-time.core :as time]))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Utils protocols related to time checking
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol ITimestamp
  "Default protocol for convert any type to
  unix timestamp in UTC."
  (to-timestamp [obj] "Covert to timestamp"))

(extend-protocol ITimestamp
  java.util.Date
  (to-timestamp [obj]
    (let [date (coerce/from-date obj)]
      (quot (coerce/to-long date) 1000)))

  org.joda.time.DateTime
  (to-timestamp [obj]
    (let [date (time/to-time-zone obj time/utc)]
      (quot (coerce/to-long date) 1000))))

(defn timestamp
  "Get a current timestamp."
  []
  (let [date (time/now)]
    (to-timestamp date)))
