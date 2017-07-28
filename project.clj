(defproject buddy/buddy-sign "1.6.0"
  :description "High level message signing for Clojure"
  :url "https://github.com/funcool/buddy-sign"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.9.0-alpha17" :scope "provided"]
                 [com.taoensso/nippy "2.13.0" :scope "provided"]
                 [org.clojure/test.check "0.9.0" :scope "test"]
                 [buddy/buddy-core "1.2.0"]
                 [cheshire "5.7.1"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])

