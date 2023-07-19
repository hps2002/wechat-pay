#ifndef __WECHAT_H__
#define __WECHAT_H__

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <httplib.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

#include "../log/log.h"
#include "../../util/util.h"
#include "../config/config.h"

namespace wechat {
// 预下单
boost::json::value OrderPay(const std::string open_id, const std::string order_serial, const int total, std::stringstream& message);
// 获取预下单ID
std::string getPrepayId(const std::string open_id, const std::string order_serial, const int total);
// 获取签名信息
std::string getSignatureMessage(const std::string methor, const std::string body, std::stringstream& message);
// 获取鉴权头
std::string getAuthorization(const std::string methor, const std::string body, std::stringstream& message);
// 获取Base64编码的签名值
std::string getSignVal(const std::string SignStr, std::stringstream& message);
// 使用私钥进行签名
std::string SginWithRSA(const std::string SignStr, std::stringstream& message);
// 进行Base64编码
std::string Base64Encode(const std::string binSignature);
// 签名验证
bool signatureVer(httplib::Result& response, std::stringstream& message);
// 下载微信证书
bool getWXcert(std::stringstream& message);
// base64解码
std::string base64Decode(const std::string& encodedString);
// sha256哈希值
void sha256(const unsigned char* data, size_t len, unsigned char* hash);
// RSA签名验证
bool Rsa_PublicVerify(const char *filename, unsigned char *data, int datalen, std::string sign, int signlen, std::stringstream& message);
// 密文解密
std::string gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, 
                unsigned char *tag, unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext, std::stringstream& message);
// 更新公钥
bool RenewPubKey ();
// 更新序列序列号
bool RenewWXserialNo();
}

#endif
