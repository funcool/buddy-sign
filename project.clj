(defproject buddy/buddy-sign "2.2.0"
  :description "High level message signing for Clojure"
  :url "https://github.com/funcool/buddy-sign"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.9.0-alpha19" :scope "provided"]
                 [com.taoensso/nippy "2.13.0" :scope "provided"]
                 [org.clojure/test.check "0.9.0" :scope "test"]
                 [buddy/buddy-core "1.4.0"]
                 [cheshire "5.8.0"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])

