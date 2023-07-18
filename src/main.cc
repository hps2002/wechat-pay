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

}