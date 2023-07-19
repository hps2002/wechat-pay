# 配置模块
通过编写一个简单的 `Config` 类用于解析配置 `json` 文件。引用第三方 `boost` 库，如果没有的话请[下载](https://www.boost.org/) `boost` 库并且编译安装，然后在构建的项目中进行连接。

安装 `boost` 库步骤：
```bash
$ cd ~/boost
$ bash ./bootstrap.sh 
$ sudo ./b2 #编译
$ sudo ./b2 headers #生成头文件
$ sudo ./b2 install #安装 -- 默认路径是/usr/local
```

在 `CMakeLists.txt` 中:
```txt
include_directories(/usr/local/include)
link_directories(/usr/local/lib)
find_package(Boost REQUIRED COMPONENTS json)
target_link_libraries(test PRIVATE Boost::json)
```  
在 `Config` 类中通过 `Load` 函数将 `json` 中的解析出来，使用的是单例模式。  
获取配置变量的方法是 `auto cfg = wechat::Config::Get();`  
