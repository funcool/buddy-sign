(defproject buddy/buddy-sign "3.4.0"
  :description "High level message signing for Clojure"
  :url "https://github.com/funcool/buddy-sign"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.10.3" :scope "provided"]
                 [com.taoensso/nippy "3.1.1" :scope "provided"]
                 [buddy/buddy-core "1.10.0"]]
  :jar-name "buddy-sign.jar"
  :source-paths ["src"]
  :javac-options ["-target" "1.8" "-source" "1.8" "-Xlint:-options"]
  :test-paths ["test"])

