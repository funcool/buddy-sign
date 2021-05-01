{:dev
 {:aliases {"test-all" ["with-profile" "dev:dev,1.9:dev,1.8:dev" "test"]}
  :plugins
  [[lein-codox "0.10.7"]
   [lein-ancient "0.7.0"]]

  :dependencies
  [[org.clojure/tools.reader "1.3.5"]
   [org.clojure/test.check "1.1.0" :scope "test"]
   [com.nimbusds/nimbus-jose-jwt "4.13.1"]
   [codox-theme-rdash "0.1.2"]]

  :codox
  {:project {:name "buddy-sign"}
   :metadata {:doc/format :markdown}
   :output-path "doc/dist/latest/"
   :doc-paths ["doc/"]
   :themes [:rdash]
   :source-paths ["src"]
   :source-uri "https://github.com/funcool/buddy-sign/blob/master/{filepath}#L{line}"
   :namespaces [#"^buddy\."]}}

 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}}
