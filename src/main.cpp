#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <jwt-cpp/jwt.h>
#include <iostream>
#include <bcrypt/BCrypt.hpp>
#include <httplib.h>
#include <sstream>
#include <fstream>

std::string pr_key;
std::string pb_key;

std::string ReadFile(const std::string& path)
{
  const std::ifstream     file_stream{path};
        std::stringstream ss{};
  ss << file_stream.rdbuf();

  return ss.str();
}

void ReadKeys(const std::string& private_path, const std::string& public_path)
{
  pr_key = "";
  pb_key = "";
}

std::string DoLogin(const std::string& username, const std::string& password)
{
  auto token = jwt::create()
    .set_issuer       ("kiq")
    .set_type         ("JWT")
    .set_id           ("kiq_auth_example")
    .set_issued_at    (std::chrono::system_clock::now())
    .set_expires_at   (std::chrono::system_clock::now() + std::chrono::seconds(86400))
    .set_payload_claim("user", jwt::claim(std::string{username}))
    .sign             (jwt::algorithm::es256k(pb_key, pr_key, "", ""));

  auto verify  = jwt::verify()
    .allow_algorithm(jwt::algorithm::es256k(pb_key, pr_key, "", ""))
    .with_issuer    ("kiq");
  auto decoded = jwt::decode(token);
  auto hash    = BCrypt::generateHash(password);

  verify.verify(decoded);

  for (auto&& e : decoded.get_payload_claims())
    std::cout << e.first << " = " << e.second.to_json() << std::endl;

  std::cout << BCrypt::validatePassword(password, hash) << std::endl;
  std::cout << "Hashed password is: " << hash << std::endl;

  return token;
}

int main(int argc, char* argv[])
{
  auto GetJSON = [](const auto& token) { return "{\"token\":\"" + token + "\"}"; };
  if (argc < 3) throw std::invalid_argument{"Please path to public and private keys"};

  pr_key = ReadFile(argv[1]);
  pb_key = ReadFile(argv[2]);

  httplib::Server svr;

  svr.Get("/", [&GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    std::string name, pass;
    if (req.has_param("name"))
      name = req.get_param_value("name");

    if (req.has_param("password"))
      pass = req.get_param_value("password");

    res.set_content(GetJSON(DoLogin(name, pass)), "application/json");
  });

  svr.listen("0.0.0.0", 8080);

  return 0;
}
