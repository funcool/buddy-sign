(defproject buddy/buddy-sign "3.1.0"
  :description "High level message signing for Clojure"
  :url "https://github.com/funcool/buddy-sign"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.10.1" :scope "provided"]
                 [com.taoensso/nippy "2.14.0" :scope "provided"]
                 [org.clojure/test.check "0.9.0" :scope "test"]
                 [buddy/buddy-core "1.6.0"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])

