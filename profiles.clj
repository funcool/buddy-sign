{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.7:dev,1.8:dev" "test"]}
  :dependencies [[com.nimbusds/nimbus-jose-jwt "4.13.1"]]
  :codeina {:sources ["src"]
            :reader :clojure
            :target "doc/dist/latest/api"
            :src-uri "http://github.com/funcool/buddy-core/blob/master/"
            :src-uri-prefix "#L"}
  :plugins [[funcool/codeina "0.4.0"]
            [lein-ancient "0.6.10"]]}
 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}}
