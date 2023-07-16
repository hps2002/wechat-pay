#include "config.h"

namespace wechat{

Config& Config::Get () {
  static Config cfg;
  return cfg;
}

static boost::json::value Load(const char *path) {
  std::ifstream file(path);
  std::stringstream cfg_buf;
  cfg_buf << file.rdbuf();
  file.close();
  boost::json::value config = boost::json::parse(cfg_buf.str()); 
  return config;
}

Config::Config () {
  try {
    using boost::json::value_to;
    auto j = Load(std::string("../../config/wxpay.json").c_str());
    wechat.appid = value_to<std::string>(j.at("appid"));
    wechat.mchid = value_to<std::string>(j.at("mchid"));
    wechat.clientPrivateKeyPath = value_to<std::string>(j.at("clientPrivateKeyPath"));
    wechat.clientCertPath = value_to<std::string>(j.at("clientCertPath"));
    wechat.WechatCertPath = value_to<std::string>(j.at("WechatCertPath"));
    wechat.WechatPublicKeyPath = value_to<std::string>(j.at("WechatPublicKeyPath"));
    wechat.Description = value_to<std::string>(j.at("Description"));
    wechat.AuthenticationType = value_to<std::string>(j.at("AuthenticationType"));
    wechat.apiv3key = value_to<std::string>(j.at("apiv3key"));
    wechat.wx_serial_no = value_to<std::string>(j.at("wx_serial_no"));
    wechat.client_serial_no = value_to<std::string>(j.at("client_serial_no"));
    wechat.notify_url = value_to<std::string>(j.at("notify_url"));
    wechat.backup_path = value_to<std::string>(j.at("backup_path"));
    wechat.wxpayCfg_path = value_to<std::string>(j.at("wxpayCfg_path"));
    wechat.wxLogPath = value_to<std::string>(j.at("wxLogPath"));
  }
  catch (std::exception e)
  {
    std::cerr << e.what() << std::endl;
  } 
  catch(...)
  {
    std::cout << "Error occured when reading config files" << std::endl;
    exit(1);
  }
}
}