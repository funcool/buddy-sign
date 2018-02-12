;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
;; Copyright (c) 2017 Denis Shilov <sxp@bk.ru>
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

(ns buddy.sign.jwk-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [buddy.core.keys :as keys]
            [buddy.sign.jws :as jws]))

(defn- load-pair [jwk]
  [(keys/jwk->public-key jwk)
   (keys/jwk->private-key jwk)])

(def ed25519-jwk-key
  {:kty "OKP"
   :crv "Ed25519"
   :d "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(deftest ed25519-jws-sign-unsign
  (let [[public private] (load-pair ed25519-jwk-key)
        ;; Example from RFC
        payload "Example of Ed25519 signing"
        token (jws/sign payload private {:alg :eddsa :key private})]

    (is (= "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
           token))
    (is (= "Example of Ed25519 signing"
           (codecs/bytes->str (jws/unsign token public {:alg :eddsa}))))))

(def rsa2048-jwk-key
  {:kty "RSA",
   :n "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
   :e "AQAB"
   :d "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"})


(deftest rsa-jws-sign-unsign
  (let [[public private] (load-pair rsa2048-jwk-key)
        ;; Example from RFC
        payload "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        token (jws/sign payload private {:alg :rs256
                                         :key private})]

    (is (= "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
           token))
    (is (= payload
           (codecs/bytes->str (jws/unsign token public {:alg :rs256}))))))

(def ec256-jwk-key
  {:kty "EC",
   :crv "P-256",
   :x "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
   :y "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
   :d "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"})

(deftest ec256-jws-sign-unsign
  (let [[public private] (load-pair ec256-jwk-key)
        payload "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        token (jws/sign payload private {:alg :es256
                                         :key private})
        rfctoken "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"]

    ;; unsign using our token
    (is (= payload
           (codecs/bytes->str (jws/unsign token public {:alg :es256}))))

    ;; unsign using RFC reference token
    (is (= payload
           (codecs/bytes->str (jws/unsign rfctoken public {:alg :es256}))))))


(def ec521-jwk-key
  {:kty "EC",
   :crv "P-521",
   :x "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
   :y "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
   :d "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"})

(deftest ec521-jws-sign-unsign
  (let [[public private] (load-pair ec521-jwk-key)
        payload "Payload"
        token (jws/sign payload private {:alg :es512
                                         :key private})
        rfctoken "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"]

    ;; unsign using our token
    (is (= payload
           (codecs/bytes->str (jws/unsign token public {:alg :es512}))))
    ;; unsign using RFC reference token
    (is (= payload
           (codecs/bytes->str (jws/unsign rfctoken public {:alg :es512}))))))
