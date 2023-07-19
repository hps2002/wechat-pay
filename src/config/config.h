#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <iostream>
#include <string>
#include <boost/json.hpp>
#include <memory>
#include <fstream>
#include <sstream>

namespace wechat{

class Config {
public:
  struct {
    std::string appid;
    std::string mchid;
    std::string clientPrivateKeyPath;
    std::string clientCertPath;
    std::string WechatCertPath;
    std::string WechatPublicKeyPath;
    std::string Description;
    std::string AuthenticationType;
    std::string apiv3key;
    std::string wx_serial_no;
    std::string client_serial_no;
    std::string notify_url;
    std::string backup_path;
    std::string wxpayCfg_path;
    std::string wxLogPath;
    std::string HttpsCert;
    std::string HttpsKey;
  } wechat;
  
  static Config& Get();
private:
  Config();
};
boost::json::value Load(const char *path);
}
#endif