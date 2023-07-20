#include "./wechat/wechat.h"
#include "./log/log.h"
#include "./config/config.h"

namespace wechat {
boost::json::value OrderPay(const std::string open_id, const std::string order_serial, const int total) {
  std::stringstream ss;
  try {
    auto cfg = Config::Get();
    std::string appid = cfg.wechat.appid,
                timestamp = "",
                nonce = "",
                package = "prepay_id=";
    
    timestamp = GetTime();
    if (timestamp.size() == 0)
    {
      ss << GET_PLACE << "timestamp size = 0.";
      throw Level::ERROR;
    }

    nonce = GetNonce();
    if (nonce.size() == 0)
    {
      ss << GET_PLACE << "nonce size = 0.";
      throw Level::ERROR;
    }

    std::string prepay_id = getPrepayId(open_id, order_serial, total);
    if (prepay_id.size() == 0)
    {
      ss << GET_PLACE << "prepay_id is null.";
      throw Level::ERROR;
    }
    package += prepay_id;

    std::string paySign = "",
                SignStr = appid + "\n" +
                          timestamp + "\n" +
                          nonce + "\n" +
                          package + "\n";
    paySign = getSignVal(SignStr, ss);

    boost::json::object pck{
      {"appId", appid},
      {"timeStamp", timestamp},
      {"nonceStr", nonce},
      {"package", package},
      {"signType", "RSA"},
      {"paySign", paySign}
    };
    return pck;
  } catch (std::exception e) {
    ss << GET_PLACE << e.what();
    wechat::Logger::log(ss, wechat::Level::ERROR);
  } catch (wechat::Level::level level) { 
    wechat::Logger::log(ss, level);
  }
}

boost::json::value PayCallBack(httplib::Request& request) {
  std::stringstream message;
  try {
    auto cfg = Config::Get();
    if (!signatureVer(request, message)) {
      MESSAGE << "PayCallBack signature Veritify faild.";
      throw Level::ERROR;
    }

    auto resource = boost::json::parse(request.body).as_object();
    auto body = boost::json::parse(boost::json::value_to<std::string>(resource["resource"])).as_object();
    std::string ciphertext = boost::json::value_to<std::string>(body["ciphertext"]),
                nonce = boost::json::value_to<std::string>(body["nonce"]), 
                associated_data = boost::json::value_to<std::string>(body["associated_data"]);
    
    unsigned char buf[2048];
    std::string plaintext = gcm_decrypt((unsigned char*)ciphertext.c_str(), ciphertext.size(), (unsigned char*)associated_data.c_str(), associated_data.size(), NULL, (unsigned char*)cfg.wechat.apiv3key.c_str(), (unsigned char*)nonce.c_str(), nonce.size(), buf, message);

    boost::json::value res = boost::json::parse(plaintext);
    return res;
  } catch (std::exception e) {
    MESSAGE << GET_PLACE << e.what();
    wechat::Logger::log(message, Level::ERROR);
  } catch (wechat::Level::level level) {
    wechat::Logger::log(message, level);
  }
}

bool ReplyWechat() {
  std::stringstream message;
  try {
    if(!ReplyWechat_aux(message)) {
      MESSAGE << "reply wechat error.";
      throw Level::WARING;
    }
    return true;
  } catch (std::exception e) {
    MESSAGE << e.what();
    throw Level::ERROR;
  } catch (wechat::Level::level level) {
    wechat::Logger::log(message, wechat::Level::ERROR);
  }
}

}