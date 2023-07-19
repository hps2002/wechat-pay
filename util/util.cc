#include "util.h"

namespace wechat {

std::string GetTime() {
  std::time_t cur = std::time(nullptr);
  std::tm* lc = std::localtime(&cur);
  std::string curTime = std::to_string(lc -> tm_year + 1900) + "-" + 
                        std::to_string(lc -> tm_mon + 1) + "-" +
                        std::to_string(lc -> tm_mday) + " " +
                        std::to_string(lc -> tm_hour) + ":" +
                        std::to_string(lc -> tm_min) + ":" +
                        std::to_string(lc -> tm_sec);
  return curTime;
}

std::string GetTimestamp() {
  time_t now = time(NULL);
  std::string timestamp = std::to_string(now);
  return timestamp;
}

std::string GetNonce() {
    std::string noncestr = "";
    std::random_device rd;
    std::mt19937 gen(rd());
    const int str_length = 32;
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    for (int i = 0; i < str_length; ++i)
        noncestr += chars[dis(gen)];
    return noncestr;
}

}