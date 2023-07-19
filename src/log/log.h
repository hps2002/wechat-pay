#ifndef __LOG_H__
#define __LOG_H__

#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <memory>

#include "../../src/config/config.h"
#include "../../util/util.h"

namespace wechat{

#define GET_PLACE "| [" << __FILE__ << ":" << __LINE__ << " " << __func__ << "] " 
#define MESSAGE message << GET_PLACE
#define LOG(message, level) \
{ \
  wechat::Logger::log(message, level); \
}

class Level {
public:
  enum level {
    DEBUG = 0,
    INFO = 1,
    WARING = 2,
    ERROR = 3,
    FATAL = 4
  };
};

// 完成日志记录
class Logger
{
public:
  typedef std::shared_ptr<Logger> ptr;
  static void log(std::stringstream& message, Level::level levle);
  static std::string getLevel(Level::level level);
private:
  std::stringstream message;
};
}


#endif