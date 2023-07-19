# 简介
这是一个使用 C++ 对项目中需要使用JSAPI进行微信支付接入的组件。接入的微信支付接口是 `JSAPIv3`。 
|环境|说明|
|:-|:-|
|ubuntu 22|操作系统环境
|openssl|加解密操作开源库
|boost|解析json包用于通信
|httplib|发送网络数据包的库

在使用组件之前需要安装上面的一些开源库，其中如果 `boost/json` 库如果不是动态连接的话需要将组件中关于 `boost/json` 库的头文件更改为 `#include <boost/json/src.hpp>` 改为静态库应用，其他的库最好下载后安装到本地作为动态库进行连接。 

本组件拥有自己的[日志系统](/doc/Log.md)，可以通过修改配置文件中日志的 `输出路径` 和 `日志格式` 与实际项目的日志的输出路径进行日志融合。

本组件拥有自己的[配置系统](/doc/Config.md), 支持自己修改配置，实现组件的健壮性。

# 使用说明  
本组件所做的工作主要有：获取前端传递的商户订单号，总金额， `open_id` 来向微信支付获取 `prepay_id` 完成预支付，将获取到的 `prepay_id` 按照官方文档打包好发给前端。 


## 使用前
使用前需要将关于自己商户信息在 `wxpay.json` 中进行配置，然后即可使用。

**关于 `wxpay.json` 文件说明**
|参数|说明|
|:-|:-|
|  "appid"| 微信生成的应用ID
|  "mchid"| 直连商户号
|  "clientPrivateKeyPath"| 商户私钥路径，文件格式是.pem
|  "clientCertPath" | 商户证书路径，文件格式是.pem
|  "WechatCertPath" | 微信平台证书路径，文件格式是.pem
|  "WechatPublicKeyPath" | 微信平台证书的公钥，文件格式是.pem
|  "Description" | 商品描述
|  "AuthenticationType" | 认证类型，但是目前微信有规定的认证类型，具体的话建议去微信开发文档确认
|  "apiv3key" | 商户的32位apiv3的密钥
|  "wx_serial_no" | 微信证书的序列号
|  "client_serial_no" | 商户证书的序列号
|  "notify_url" | 支付回调路径
|  "backup_path" | 配置文件的备份路径
|  "wxpayCfg_path" | 配置文件的备份
|  "wxpayLogPath" | 组件日志路径
|  "wxpayLogFormat" | 输出日志格式



# 使用样例
