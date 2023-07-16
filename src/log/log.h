#ifndef __LOG_H__
#define __LOG_H__

#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <memory>

#include "../../src/config/config.h"
#include "../../util/Timer.h"

namespace wechat{

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