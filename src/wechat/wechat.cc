#include "wechat.h"

namespace wechat {

const std::string payurl = "/v3/pay/transactions/jsapi";
const std::string certurl = "/v3/certificates";
const std::string refundUrl = "/v3/refund/domestic/refunds";
const std::string checkOrderUrl = "/v3/pay/transactions/out-trade-no/";
const std::string closeOrderUrl = "/v3/pay/transactions/out-trade-no/";
httplib::SSLClient cli("api.mch.weixin.qq.com");

std::string getPrepayId(const std::string open_id, const std::string order_serial, const int total, std::stringstream& message) {
  auto cfg = Config::Get();
  boost::json::object amount{
                {"total", total},
                {"currency", "CNY"}
            },
            payer{
                {"openid", open_id}
            };
  boost::json::object body_json{
                {"mchid", cfg.wechat.mchid},
                {"out_trade_no", order_serial},
                {"appid", cfg.wechat.appid},
                {"description", cfg.wechat.Description},
                {"notify_url", cfg.wechat.notify_url},
                {"amount", amount},
                {"payer", payer}
            };
  std::string body = boost::json::serialize(body_json);
  std::string Authorization = getAuthorization("POST", body, message);

  httplib::Headers headers;
  headers.emplace("Authorization", Authorization);
  headers.emplace("Content-Type", "application/json");
  headers.emplace("Accept", "application/json");
  auto response = cli.Post(payurl, headers, body, "application/json");
  if (response.error() != httplib::Error::Success) {
    message << GET_PLACE << "$getPrypreId: recieved error response.";
    throw Level::ERROR;
  }

  if (!signatureVer(response, message)) {
    message << GET_PLACE << "signature Vertify faild.";
    throw Level::ERROR;
  }

  auto res = boost::json::parse(response.value().body).as_object();
  if (res.contains("errcode")) {
    MESSAGE << "$errcode = " << boost::json::value_to<std::string>(res["errcode"]) << " $message = " << boost::json::value_to<std::string>(res["message"]);
    throw Level::ERROR;
  }
  std::string paypreId = boost::json::value_to<std::string>(res["prepay_id"]);
  return paypreId;
}

std::string getSignatureMessage(const std::string methor , const std::string body, std::stringstream& message) {
  auto cfg = Config::Get();
  std::string url = payurl,
              timestamp = "",
              nonce = "";

  timestamp = GetTimestamp();
  if (timestamp.size() == 0) {
    MESSAGE << "$timestamp size = 0.";
    throw Level::ERROR;
  }
 
  nonce = GetNonce();
  if (nonce.size() == 0) {
    MESSAGE << "$nonce size = 0.";
    throw Level::ERROR;
  }

  std::string signStr = methor + "\n" +
                        payurl + "\n" + 
                        timestamp + "\n" +
                        nonce + "\n" + 
                        body + "\n";
  std::string signature = getSignVal(signStr, message);
  if (signature.size() == 0)
  {
    MESSAGE << "$signature size = 0.";
    throw Level::ERROR;
  }

  std::string sigMessage = std::string(" mchid=") + std::string("\"") +  cfg.wechat.mchid + std::string("\",")
            + std::string("serial_no=") + std::string("\"") + cfg.wechat.client_serial_no + std::string("\",")
            + std::string("nonce_str=") + std::string("\"") + nonce + std::string("\",")
            + std::string("timestamp=") + std::string("\"") + timestamp + std::string("\",")
            + std::string("signature=") + std::string("\"") + signature + std::string("\"");

  return sigMessage;
}

std::string getAuthorization(const std::string methor, const std::string body, std::stringstream& message) {
  auto cfg = Config::Get();
  std::string Authorization = cfg.wechat.AuthenticationType, 
              sigMessage = getSignatureMessage(methor, body, message);
  Authorization += sigMessage;
  return Authorization;
}

std::string getSignVal(const std::string SignStr, std::stringstream& message) {
  std::string binSignature = SginWithRSA(SignStr, message);
  std::string Signature = Base64Encode(binSignature);
  return Signature;
}

std::string SginWithRSA(const std::string SignStr, std::stringstream& message) {
  auto cfg = Config::Get();
  FILE* privateKeyFile = fopen(cfg.wechat.clientPrivateKeyPath.c_str(), "r");
    if (!privateKeyFile) {
        MESSAGE << "Can't open privateKey File";
        throw Level::ERROR;
    }

    EVP_PKEY* privateKey = PEM_read_PrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    if (!privateKey) {
        MESSAGE << "Failed to read private key";
        throw Level::ERROR;
    }

    RSA* rsaPrivateKey = EVP_PKEY_get1_RSA(privateKey);
    EVP_PKEY_free(privateKey);

    if (!rsaPrivateKey) {
        MESSAGE << "Failed to get RSA private key";
        throw Level::ERROR;
    }

    unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(SignStr.data()), SignStr.length(), sha256Hash);

    unsigned char signature[RSA_size(rsaPrivateKey)];
    unsigned int signatureLength;

    int result = RSA_sign(NID_sha256, sha256Hash, SHA256_DIGEST_LENGTH, signature, &signatureLength, rsaPrivateKey);
    RSA_free(rsaPrivateKey);

    if (result != 1) {
        MESSAGE << "Failed to sign raw_signature";
        throw Level::ERROR;
    }

    return std::string(reinterpret_cast<const char*>(signature), signatureLength);
}

std::string Base64Encode(const std::string binSignature) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO* memBio = BIO_new(BIO_s_mem());
    BIO_push(bio, memBio);

    BIO_write(bio, binSignature.data(), binSignature.length());
    BIO_flush(bio);

    char* encodedBuffer;
    long encodedSize = BIO_get_mem_data(memBio, &encodedBuffer);
    std::string base64Encoded(encodedBuffer, encodedSize);
    BIO_free_all(bio);
    return base64Encoded;
}

bool signatureVer(httplib::Result& response, std::stringstream& message) {
  auto cfg = Config::Get();
  httplib::Headers headers;
  headers = response -> headers;

  auto it_serial = headers.find("Wechatpay-Serial");
  if (it_serial == headers.end()) {
    MESSAGE << "haders haven't Wechatpay-Serial.";
    LOG(message, Level::WARING);
  }
  
 if (it_serial -> second != cfg.wechat.mchid) {
    if (!getWXcert(message)) {
      MESSAGE << "get Wechat's cert faild.";
     throw Level::ERROR; 
    }
 } 

  auto it_nonce = headers.find("Wechatpay-Nonce"),
       it_sig = headers.find("Wechatpay-Signature"),
       it_timestamp = headers.find("Wechatpay-Timestamp");
  
  std::string nonce = it_nonce -> second,
              timestamp = it_timestamp -> second,
              signature = it_sig -> second;
  
  auto body = boost::json::parse(response.value().body).as_object();
  std::string ciphertext = boost::json::value_to<std::string>(body["ciphertext"]),
              iv = boost::json::value_to<std::string>(body["nonce"]),
              aad = boost::json::value_to<std::string>(body["associated_data"]),
              bodyStr = boost::json::serialize(body),
              sigStr = timestamp + "\n" + 
                       nonce + "\n" + 
                       bodyStr + "\n";
  bool ans = Rsa_PublicVerify(cfg.wechat.WechatPublicKeyPath.c_str(), (unsigned char*)sigStr.c_str(), sigStr.size(), signature, signature.size(), message);

  return false;
}

bool signatureVer(httplib::Request& response, std::stringstream& message) {
  auto cfg = Config::Get();
  httplib::Headers headers;
  headers = response.headers;

  auto it_serial = headers.find("Wechatpay-Serial");
  if (it_serial == headers.end()) {
    MESSAGE << "haders haven't Wechatpay-Serial.";
    LOG(message, Level::WARING);
  }
  
 if (it_serial -> second != cfg.wechat.mchid) {
    if (!getWXcert(message)) {
      MESSAGE << "get Wechat's cert faild.";
     throw Level::ERROR; 
    }
 } 

  auto it_nonce = headers.find("Wechatpay-Nonce"),
       it_sig = headers.find("Wechatpay-Signature"),
       it_timestamp = headers.find("Wechatpay-Timestamp");
  
  std::string nonce = it_nonce -> second,
              timestamp = it_timestamp -> second,
              signature = it_sig -> second;
  
  auto body = boost::json::parse(response.body).as_object();
  std::string ciphertext = boost::json::value_to<std::string>(body["ciphertext"]),
              iv = boost::json::value_to<std::string>(body["nonce"]),
              aad = boost::json::value_to<std::string>(body["associated_data"]),
              bodyStr = boost::json::serialize(body),
              sigStr = timestamp + "\n" + 
                       nonce + "\n" + 
                       bodyStr + "\n";
  bool ans = Rsa_PublicVerify(cfg.wechat.WechatPublicKeyPath.c_str(), (unsigned char*)sigStr.c_str(), sigStr.size(), signature, signature.size(), message);

  return false;
}

bool getWXcert(std::stringstream& message) {
  auto cfg = Config::Get();
  std::string Authorization = getAuthorization("GET", "", message);
  std::cout << Authorization << std::endl;
  if (Authorization.size() <= cfg.wechat.AuthenticationType.size()) {
    MESSAGE << "wrong Authorization.";
    throw Level::ERROR;
  }
  httplib::Headers headers;
  headers.emplace("Ayinuthorization", Authorization);
  headers.emplace("Content-Type", "application/json");
  headers.emplace("Accept", "application/json");
  auto response = cli.Get(certurl, headers);
  if (response.error() != httplib::Error::Success) {
    MESSAGE << httplib::to_string(response.error());
    throw Level::ERROR;
  }

  auto res = boost::json::parse(response.value().body).as_object();
  if (!res.contains("ciphertext"))
  {
    MESSAGE << "Bad response";
    throw Level::ERROR;
  }

  std::string ciphertext = boost::json::value_to<std::string>(res["ciphertext"]),
              nonce = boost::json::value_to<std::string>(res["nonce"]),
              associate_data = boost::json::value_to<std::string>(res["associate_data"]);
  
  unsigned char buff[2048];
    std::string plaintext = gcm_decrypt((unsigned char *)ciphertext.c_str(), ciphertext.size(),
    (unsigned char*)associate_data.c_str(), associate_data.size(), NULL, (unsigned char*)cfg.wechat.apiv3key.c_str(), (unsigned char*)nonce.c_str(), nonce.size(), buff, message);

  // 备份文件
  std::ofstream file(cfg.wechat.backup_path, std::ios::out | std::ios::trunc);
  if (!file) {
    MESSAGE << "backup file open faild.";
    throw Level::ERROR;
  }
  auto val = Load(cfg.wechat.backup_path.c_str());
  std::string backupStr = boost::json::serialize(val);
  file << backupStr;
  file.close();

  // 更新公钥
  if (!RenewPubKey()) {
    MESSAGE << "renewWXcert faild.";
    throw Level::ERROR;
  }
  // 更新序列号
  if (!RenewWXserialNo()) {
    MESSAGE << "renewPublicKey faild";
    throw Level::ERROR;
  }
  // 更新配置文件
  val = Load(cfg.wechat.wxpayCfg_path.c_str());
  auto param = val.as_object();
  std::string newFile = boost::json::serialize(param);
  std::ofstream f(cfg.wechat.wxpayCfg_path.c_str());
  f << newFile;
  f.close();
  return true;
}

std::string base64Decode(const std::string& encodedString) {
    std::string decodedString;
    BIO* bio = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO* bioMem = BIO_new_mem_buf(encodedString.c_str(), encodedString.length());
    bio = BIO_push(bio, bioMem);
    decodedString.resize(encodedString.length());
    int decodedLength = BIO_read(bio, &decodedString[0], encodedString.length());
    decodedString.resize(decodedLength);
    BIO_free_all(bio);
    return decodedString;
}

void sha256(const unsigned char* data, size_t len, unsigned char* hash) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned int md_len;
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);
}

bool Rsa_PublicVerify(const char *filename, unsigned char *data, int datalen, std::string sign, int signlen, std::stringstream& message) {
    FILE* pubFile = fopen(filename, "r");
    if (!pubFile) {
        MESSAGE << "can't load pubkeyFile";
        throw Level::ERROR;
    }

    RSA* rsaPub = PEM_read_RSA_PUBKEY(pubFile, NULL, NULL, NULL);
    fclose(pubFile);
    if (!rsaPub) {
        MESSAGE << "can't read pubkey";
        throw Level::ERROR;
    }
    std::string sig = base64Decode(sign);

    unsigned char HashData[SHA256_DIGEST_LENGTH];
    sha256(data, datalen, HashData);
    
    int result = RSA_verify(NID_sha256, HashData, sizeof(HashData), (unsigned char*)sig.c_str(), sig.size(), rsaPub);
    if (result != 1) {
        MESSAGE << "signature vertify faild.";
        RSA_free(rsaPub);
        throw Level::ERROR;
    }
    return true;
}

std::string gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, 
                unsigned char *tag, unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext, std::stringstream& message) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        MESSAGE << "gcm_decrypt create ctx error!";
        throw Level::ERROR;
        return "";
    }
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        MESSAGE << "gcm_decrypt init error!";
        throw Level::ERROR;
        return "";
    }
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        MESSAGE << "gcm_decrypt set iv error!";
        throw Level::ERROR;
        return "";
    }
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        MESSAGE << "gcm_decrypt init key && iv error!";
        throw Level::ERROR;
        return "";
    }
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        MESSAGE << "$gcm_decrypt set aad error!";
        throw Level::ERROR;
        return "";
    }
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        MESSAGE << "gcm_decrypt Decode error!";
        throw Level::ERROR;
        return "";
    }
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    std::string res = "";
    for (int i = 0; i < 1024; i ++)
        if (plaintext[i] >= 0 && plaintext[i] <= 128)
            res += plaintext[i];
        else 
            continue;
    return res;
}

bool RenewPubKey () {
  auto cfg = Config::Get();
  std::string cmd = "openssl x509 -in " + cfg.wechat.WechatCertPath + " -pubkey -noout > " + cfg.wechat.WechatPublicKeyPath;
  std::string pubkey = Popen(cmd.c_str());
  return pubkey.size() > 0;
}

bool RenewWXserialNo() {
  auto cfg = Config::Get();
  std::string cmd = "openssl x509 -in " + cfg.wechat.wx_serial_no + " -noout -serial";
  std::string str = Popen(cmd.c_str());
  int index = str.find("=");
  if (index == std::string::npos) return false;
  str = str.substr(index + 1, str.size() - index);
  cfg.wechat.wx_serial_no = str;
  return true;
}

boost::json::value PayCallBack_aux(httplib::Request request, std::stringstream& message) {
  auto cfg = Config::Get();
  if (!signatureVer(request, message)) {
    MESSAGE << "PayCallBack signature Veritify faild.";
    throw Level::ERROR;
  }

  auto resource = boost::json::parse(request.body).as_object();
  auto body = boost::json::parse(boost::json::value_to<std::string>(resource["resource"])).as_object();
  std::string ciphertext = boost::json::value_to<std::string>(body["ciphertext"]),
              nonce = boost::json::value_to<std::string>(body["nonce"]), 
              associated_data = boost::json::value_to<std::string>(body["associated_data"]);
  
  unsigned char buf[2048];
  std::string plaintext = gcm_decrypt((unsigned char*)ciphertext.c_str(), ciphertext.size(), (unsigned char*)associated_data.c_str(), associated_data.size(), NULL, (unsigned char*)cfg.wechat.apiv3key.c_str(), (unsigned char*)nonce.c_str(), nonce.size(), buf, message);

  boost::json::value res = boost::json::parse(plaintext);
  return res;
}

bool ReplyWechat_aux(std::stringstream& message) {
  boost::json::object data{
    {"code", "SUCCESS"},
    {"message", "成功"}
  };
  cli.Post(payurl, boost::json::serialize(data), "application/json");
  return true;
}

boost::json::value Refund_aux(const std::string out_trade_no, const std::string out_refund_no, std::string reason, const int refundTotal, const int total, std::stringstream& message) {
  auto cfg = Config::Get();
    if (reason.size() == 0) 
    reason = "普通退款";
  boost::json::object amout{
    {"refund", refundTotal},
    {"total", total},
    {"currency", "CNY"} 
  },
                      body{
    {"out_trade_no", out_trade_no},
    {"out_refund_no", out_refund_no}, 
    {"reason", reason},
    {"amout", amout}
  };

  std::string Authorization = getAuthorization("POST", boost::json::serialize(body), message);
  
  httplib::Headers headers;
  headers.emplace("Authorization", Authorization);
  headers.emplace("Content-Type", "application/json");
  headers.emplace("Accept", "application/json");
  auto response = cli.Post(refundUrl, headers, boost::json::serialize(body), "application/json"); 
  if (response.error() != httplib::Error::Success) {
    MESSAGE << "refund response has falid";
    throw Level::ERROR;
  }

  if (!signatureVer(response, message)) {
    MESSAGE << "signature Vertify Bad";
    throw Level::ERROR;
  }

  auto res = boost::json::parse(response.value().body).as_object();
  if (res.contains("errcode")) {
    MESSAGE << "$errcode = " << boost::json::value_to<std::string>(res["errcode"]) << "$message: " << boost::json::value_to<std::string>(res["message"]);
    Logger::log(message, Level::ERROR);
  }
  
  return res;
}

boost::json::value OrderCheck_aux(std::string out_trade_no, std::stringstream& message) {
  auto cfg = Config::Get();
  std::string param = checkOrderUrl + out_trade_no + "?mchid=" + cfg.wechat.mchid;
  std::string Authorization = getAuthorization("Get", "", message);

  httplib::Headers headers = MakeHeaders(Authorization);
  auto response = cli.Get(param, headers);
  if (response.error() != httplib::Error::Success) {
    MESSAGE << "recieve bad response";
    throw Level::ERROR;
  }
  auto res = boost::json::parse(response.value().body).as_object();
  if (res.contains("errcode")) {
    MESSAGE << "$errcode = " << boost::json::value_to<std::string>(res["errcode"]) << "$message = " << boost::json::value_to<std::string>(res["message"]);
    throw Level::ERROR;
  }
  return res;
}

httplib::Headers MakeHeaders(std::string Authorization) {
  httplib::Headers headers;
  headers.emplace("Authorization", Authorization);
  headers.emplace("Content-Type", "application/json");
  headers.emplace("Accept", "application/json");
  return headers;
}

bool CloseOrder_aux(const std::string out_trade_no, std::stringstream&  message) {
  auto cfg = Config::Get();
  std::string param = closeOrderUrl + out_trade_no + "/close";
  boost::json::object data{
    {"mchid", cfg.wechat.mchid},
    {"out_trade_no", out_trade_no}
  };

  std::string Authorization = getAuthorization("POST", boost::json::serialize(data), message);  
  httplib::Headers headers = MakeHeaders(Authorization);
  auto response = wechat::cli.Post(param, headers, boost::json::serialize(data), "application/json");
  if (response.error() != httplib::Error::Success) {
    MESSAGE << "close order faild.";
    throw Level::ERROR;
  }
  return true;
}
}