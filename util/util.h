#ifndef __UTIL_H__
#define __UTIL_H__

#include <iostream>
#include <ctime>
#include <random>
#include <stdio.h>

#include "../src/log/log.h"

namespace wechat {

std::string GetTime();

std::string GetTimestamp();

std::string GetNonce ();

std::string Popen(const char* cmd);
}
#endif