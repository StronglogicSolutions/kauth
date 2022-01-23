#include "server.hpp"
#include "util.hpp"
#include <jwt-cpp/jwt.h>
#include <bcrypt/BCrypt.hpp>
#include <httplib.h>

static void PrintClaims(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded)
{
  for (auto&& e : decoded.get_payload_claims())
    std::cout << e.first << " = " << e.second.to_json() << std::endl;
}

Server::Server(int argc, char** argv)
: m_db(GetDatabase())
{
  if (argc < 3) throw std::invalid_argument{"Please path to public and private keys"};

  m_pr_key = ReadFile(argv[1]);
  m_pb_key = ReadFile(argv[2]);

  Init();

  m_server.listen("0.0.0.0", 8080);
}

void Server::Init()
{
  auto GetJSON = [](const auto& token) { return "{\"token\":\"" + token + "\"}"; };

  m_server.Get("/", [this, &GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    std::string name, pass;

    if (req.has_param("name"))
      name = req.get_param_value("name");
    if (req.has_param("password"))
      pass = req.get_param_value("password");

    res.set_content(GetJSON(DoLogin(name, pass)), "application/json");
  });
}

std::string Server::DoLogin(const std::string& username, const std::string& password)
{
  if (username.empty() || password.empty())
    return "";

  const auto hash = BCrypt::generateHash(password);
  BCrypt::validatePassword(password, hash);

  if (!UserExists(username)) AddUser(username, hash);

  if (!BCrypt::validatePassword(password, hash))
    return "";

  auto token = jwt::create()
    .set_issuer       ("kiq")
    .set_type         ("JWT")
    .set_id           ("kiq_auth_example")
    .set_issued_at    (std::chrono::system_clock::now())
    .set_expires_at   (std::chrono::system_clock::now() + std::chrono::seconds(86400))
    .set_payload_claim("user", jwt::claim(std::string{username}))
    .sign             (jwt::algorithm::es256k(m_pb_key, m_pr_key, "", ""));

  auto verify  = jwt::verify()
    .allow_algorithm(jwt::algorithm::es256k(m_pb_key, m_pr_key, "", ""))
    .with_issuer    ("kiq");
  auto decoded = jwt::decode(token);
  verify.verify(decoded);
  PrintClaims(decoded);
  SaveToken(token, username);
  return token;
}

bool Server::UserExists(const std::string& name)
{
  return m_db.select("users", {"id"}, CreateFilter("name", name)).size();
}

void Server::AddUser(const std::string& name, const std::string& password)
{
  m_db.insert("users", {"name", "password"}, {name, password});
}
