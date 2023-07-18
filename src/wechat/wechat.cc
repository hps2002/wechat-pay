#include "wechat.h"

namespace wechat {
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
  std::string Authorization = cfg.wechat.AuthenticationType,
              sigMessage = getSignatureMessage(body, message);

  // 要注意, Authorization 和 sigMessage中间需要一个空格，在getSignMessage函数中已经将空格包含进sigMessage中
  Authorization = Authorization + sigMessage;

  httplib::Headers headers;
  headers.emplace("Authorization", Authorization);
  headers.emplace("Content-Type", "application/json");
  headers.emplace("Accept", "application/json");
  auto response = cli.Post(payurl, headers, body, "application/json");
  if (response.error() != httplib::Error::Success) {
    message << GET_PLACE << "$getPrypreId: recieved error response.";
    throw Level::ERROR;
  }

  if (!signatureVer(response)) {
    message << GET_PLACE << "signature Vertify faild.";
    throw Level::ERROR;
  }

  auto res = boost::json::parse(response.value().body).as_object();
  if (res.contains("errcode")) {
    MESSAGE << "$errcode = " << res["errcode"] << " $message = " << res["message"].as_string();
    throw Level::ERROR;
  }
  std::string paypreId = boost::json::value_to<std::string>(res["prepay_id"]);
  return paypreId;
}

std::string getSignatureMessage(const std::string body, std::stringstream& message) {
  auto cfg = Config::Get();
  std::string methor = "POST",
              url = payurl,
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

bool signatureVer(httplib::Result&)
{
  return true;
}
}