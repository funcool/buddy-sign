;; Copyright (c) 2015-2016 Andrey Antukh <niwi@niwi.nz>
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
  (:require [buddy.core.codecs :as codecs])
  (:import java.lang.reflect.Method
           clojure.lang.Reflector))

(defprotocol ITimestamp
  "Default protocol for convert any type to
  unix timestamp."
  (to-timestamp [obj] "Covert to timestamp"))

(extend-protocol ITimestamp
  java.util.Date
  (to-timestamp [obj]
    (-> (.getTime ^java.util.Date obj)
        (quot 1000)))

  java.lang.Long
  (to-timestamp [obj] obj))

;; apply Joda-Time extensions. DateTime and Instant implement ReadableInstant so this works for both
(when-let [klass (try (Class/forName "org.joda.time.ReadableInstant")
                      (catch ClassNotFoundException _))]
  (let [[^Method method] (Reflector/getMethods klass 0 "getMillis" false)]
    (extend klass
      ITimestamp
      {:to-timestamp (fn [this]
                       (-> (.invoke method this (make-array Object 0))
                           (quot 1000)))})))

;; apply Java 8 extensions
(when-let [klass (try (Class/forName "java.time.Instant")
                      (catch ClassNotFoundException _))]
  (let [[^Method method] (Reflector/getMethods klass 0 "getEpochSecond" false)]
    (extend klass
      ITimestamp
      {:to-timestamp (fn [this]
                       (.invoke method this (make-array Object 0)))})))

(defn now
  "Get a current timestamp."
  []
  (quot (System/currentTimeMillis) 1000))

(def ^:deprecated timestamp
  "Alias to `now`."
  now)

(defmacro defalias
  [name orig]
  `(do
     (alter-meta!
      (if (.hasRoot (var ~orig))
        (def ~name (.getRawRoot (var ~orig)))
        (def ~name))
      #(conj (dissoc % :macro)
             (apply dissoc (meta (var ~orig)) (remove #{:macro} (keys %)))))
     (var ~name)))
