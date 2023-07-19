#include "log.h"

namespace wechat{
  void Logger::log(std::stringstream& message, Level::level level) {
    auto cfg = Config::Get();
    std::string path = cfg.wechat.wxLogPath;
    std::ofstream file(path.c_str(), std::ios::app);
    std::stringstream buf;
    buf << "[" << GetTime() << "] " << "[" + Logger::getLevel(level) + "] " << message.str() << "\r\n";
    file << buf.str();
    file.close();
  }

  std::string Logger::getLevel(Level::level level) {
    if (level == 0)
      return "DEBUG";
    else if (level == 1)
      return "INFO";
    else if (level == 2)
      return "WARING";
    else if (level == 3)
      return "ERROR";
    else
      return "FATAL";
  }
}