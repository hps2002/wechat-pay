#include "Timer.h"

namespace wechat {
  std::string GetTime() {
  std::time_t cur = std::time(nullptr);
  std::tm* lc = std::localtime(&cur);
  std::string curTime = std::to_string(lc -> tm_year + 1900) + "-" + 
                        std::to_string(lc -> tm_mon) + "-" +
                        std::to_string(lc -> tm_mday) + " " +
                        std::to_string(lc -> tm_hour) + "-" +
                        std::to_string(lc -> tm_min) + ":" +
                        std::to_string(lc -> tm_sec);
  return curTime;
}
}