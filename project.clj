(defproject buddy/buddy-sign "0.8.1"
  :description "High level message signing for Clojure"
  :url "https://github.com/funcool/buddy-sign"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.7.0" :scope "provided"]
                 [buddy/buddy-core "0.8.1"]
                 [com.taoensso/nippy "2.10.0"]
                 [clj-time "0.11.0"]
                 [cheshire "5.5.0"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])
