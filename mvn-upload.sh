#!/bin/sh
mvn deploy:deploy-file -Dfile=target/buddy-sign.jar -DpomFile=pom.xml -DrepositoryId=clojars -Durl=https://clojars.org/repo/
