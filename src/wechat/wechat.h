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

namespace wechat {

const std::string payurl = "/v3/pay/transactions/jsapi";
httplib::SSLClient cli("api.mch.weixin.qq.com");

// 预下单
boost::json::value OrderPay(const std::string open_id, const std::string order_serial, const int total, std::stringstream& message);
// 获取预下单ID
std::string getPrepayId(const std::string open_id, const std::string order_serial, const int total);
// 获取签名信息
std::string getSignatureMessage(const std::string body, std::stringstream& message);
// 获取Base64编码的签名值
std::string getSignVal(const std::string SignStr, std::stringstream& message);
// 使用私钥进行签名
std::string SginWithRSA(const std::string SignStr, std::stringstream& message);
// 进行Base64编码
std::string Base64Encode(const std::string binSignature);
// 签名验证
bool signatureVer(httplib::Result& response);


}

#endif