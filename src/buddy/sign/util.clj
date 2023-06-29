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
  (:require
   [buddy.core.codecs :as bc]
   [cheshire.core :as json]
   [clojure.string :as str])
  (:import
   java.lang.reflect.Method
   clojure.lang.Reflector))

(defprotocol IKeyProvider
  (resolve-key [key header] "Resolve a key"))

(defprotocol ITimestamp
  "Default protocol for convert any type to
  unix timestamp."
  (to-timestamp [obj] "Covert to timestamp"))

;; Default impl for the key provider

(extend-protocol IKeyProvider
  (Class/forName "[B")
  (resolve-key [key header] key)

  String
  (resolve-key [key header] key)

  clojure.lang.IFn
  (resolve-key [key header] (key header))

  java.security.Key
  (resolve-key [key header] key))

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
  "Get a current timestamp in seconds."
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

(defn parse-jose-header
  [^bytes data]
  (try
    (let [{:keys [alg enc] :as header} (-> data
                                           (bc/b64->bytes true)
                                           (bc/bytes->str)
                                           (json/parse-string true))]
      (when-not (map? header)
        (throw (ex-info "Message seems corrupt or manipulated"
                        {:type :validation :cause :header})))
      (cond-> header
        (string? alg) (assoc :alg (keyword (str/lower-case alg)))
        (string? enc) (assoc :enc (keyword (str/lower-case enc)))))

    (catch java.lang.IllegalArgumentException e
      (throw (ex-info "Message seems corrupt or manipulated"
                      {:type :validation :cause :header})))

    (catch java.lang.NullPointerException e
      (throw (ex-info "Message seems corrupt or manipulated"
                      {:type :validation :cause :header})))

    (catch com.fasterxml.jackson.core.JsonParseException e
      (throw (ex-info "Message seems corrupt or manipulated"
                      {:type :validation :cause :header})))))

(defn encode-jose-header
  [{:keys [alg enc] :as header}]
  (let [header (cond-> header
                 (keyword? alg)
                 (assoc :alg (case alg
                               :eddsa "EdDSA"
                               :dir   "dir"
                               (-> alg name str/upper-case)))
                 (keyword? enc)
                 (assoc :enc (str/upper-case (name enc))))]
    (-> header
        (json/generate-string)
        (bc/str->bytes)
        (bc/bytes->b64 true))))
