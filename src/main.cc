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
    return {};
  } catch (wechat::Level::level level) { 
    wechat::Logger::log(ss, level);
    return {};
  }
}

boost::json::value PayCallBack(httplib::Request& request) {
  std::stringstream message;
  try {
    boost::json::value result = PayCallBack_aux(request, message);

    return result;
  } catch (std::exception e) {
    MESSAGE << GET_PLACE << e.what();
    wechat::Logger::log(message, Level::ERROR);
    return {};
  } catch (wechat::Level::level level) {
    wechat::Logger::log(message, level);
    return {};
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
    wechat::Logger::log(message, Level::ERROR);
    return false;
  } catch (wechat::Level::level level) {
    if (level == Level::WARING)
    {
      wechat::Logger::log(message, level);
      return true;
    }
    wechat::Logger::log(message, level);
    return false;
  }
}

boost::json::value Refund(const std::string out_trade_no, const std::string out_refund_no, std::string reason, const int refundTotal, const int total) {
  std::stringstream message;
  try {
    boost::json::value result = Refund_aux(out_trade_no, out_refund_no, reason, refundTotal, total, message);

    return result;
  } catch (std::exception e) {
    MESSAGE << e.what();
    wechat::Logger::log(message, Level::ERROR);
  } catch (Level::level level) {
    wechat::Logger::log(message, level);
    return {};
  }
}

}