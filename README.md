# EasyCipher


## 概述
EasyCipher收集了几种常见的加密方法的C语言实现，并基于Android平台封装了jni接口。

提供的加密方法包括
- AES加密核心部分，不涉及模式和padding，支持128bits和256bits
- AES/CBC/PKCS5Padding
- SHA256
- HAMC-SHA256
- RSA
- ECC (ECDH, ECDSA)

注： 在Android的实现中，PKCS5Padding和PKCS7Padding结果一样。

## 来源
- AES: [https://github.com/openssl/openssl/blob/master/crypto/aes/aes_core.c](https://github.com/openssl/openssl/blob/master/crypto/aes/aes_core.c)
- SHA: [https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c](https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c)
- ECC: [https://github.com/jestan/easy-ecc](https://github.com/jestan/easy-ecc)
- RSA: 将JDK中BigInteger的modPow函数（RSA的核心部分）翻译为C语言实现。

自行实现的部分：
- RSA的填充和解析。
- AES的CBC模式、PKCS5Padding填充。
- HMAC的实现。

## 原理
https://juejin.cn/post/7051222240976699428


## License
See the [LICENSE](LICENSE) file for license rights and limitations.



