#include "server.hpp"
#include "util.hpp"
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>
#include <bcrypt/BCrypt.hpp>
#include <httplib.h>
#include <string_view>

static const char* REGISTER_KEY    {"blah"};
static const char* HTML_MARKUP     {"text/html"};
static const char* APPLICATION_JSON{"application/json"};

static void PrintClaims(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded)
{
  auto claim = decoded.get_payload_claim("user");
  auto user  = claim.as_string();               std::cout << "User: " << user  <<                       std::endl;
  for (auto&& e : decoded.get_payload_claims()) std::cout << e.first  << " = " << e.second.to_json() << std::endl;
}

static bool VerifyToken(const jwt::traits::kazuho_picojson::string_type& token, const std::string& priv_key, const std::string& pub_key)
{
  try
  {
    auto verify  = jwt::verify()
                    .allow_algorithm(jwt::algorithm::es256k(pub_key, priv_key, "", ""))
                    .with_issuer    ("kiq");
    auto decoded = jwt::decode(token);
    verify.verify(decoded);
    PrintClaims  (decoded);
    return true;
  }
  catch(const std::exception& e)
  {
    log("Exception thrown while verifying token: ", e.what());
  }
  return false;
}

static jwt::traits::kazuho_picojson::string_type
CreateToken(const std::string_view& username, const std::string& priv_key, const std::string& pub_key)
{
  return jwt::create()
              .set_issuer       ("kiq")
              .set_type         ("JWT")
              .set_id           ("kiq_auth")
              .set_issued_at    (std::chrono::system_clock::now())
              .set_expires_at   (std::chrono::system_clock::now() + std::chrono::seconds(86400))
              .set_payload_claim("user", jwt::claim(std::string{username}))
              .sign             (jwt::algorithm::es256k(pub_key, priv_key, "", ""));
}

Server::Server(int argc, char** argv)
: m_db(GetDatabase())
{
  if (argc < 3) throw std::invalid_argument{"Please provide path to private and public keys"};

  m_pr_key = ReadFile(argv[1]);
  m_pb_key = ReadFile(argv[2]);

  Init();

  m_server.listen("0.0.0.0", 9999);
}

void Server::Init()
{
  using JSON = nlohmann::json;
  auto GetJSON = [](const std::string& token)
  { return(token.size()) ? JSON{{"token", token}}.dump() : JSON{{"error", "Login failed"}}.dump(); };

  m_server.Get("/login", [this, &GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    std::string name, pass;

    if (req.has_param("name"))     name = req.get_param_value("name");
    if (req.has_param("password")) pass = req.get_param_value("password");

    res.set_content(GetJSON(Login(name, pass)), APPLICATION_JSON);
  });

  m_server.Get("/register", [this, &GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    std::string name, pass, key;

    if (req.has_param("name"))     name = req.get_param_value("name");
    if (req.has_param("password")) pass = req.get_param_value("password");
    if (req.has_param("key"))      key  = req.get_param_value("key");

    res.set_content((Register(name, pass, key)) ? "Created" : "Failed", HTML_MARKUP);
  });
}

bool Server::Register(const std::string& username, const std::string& password, const std::string& key)
{
  bool user_exists = UserExists(username);
  if (user_exists)
    log("User exists");

  if (username.empty() || password.empty() || key.empty() || user_exists || key != REGISTER_KEY) return false;
  AddUser(username, BCrypt::generateHash(password));
  log("Registration successful");
  return true;
}

std::string Server::Login(const std::string& username, const std::string& password)
{
  log("Login attempt by ", username.c_str(), " with pass ", password.c_str());

  try
  {
    if (username.size() && password.size() &&
        BCrypt::validatePassword(password, BCrypt::generateHash(password)))
    {
      log("Login validated");

      auto token = CreateToken(username, m_pr_key, m_pb_key);

      if (VerifyToken(token, m_pr_key, m_pb_key))
      {
        SaveToken(token, username);
        log("Returning token");
        return token;
      }
    }
  }
  catch(const std::exception& e)
  {
    log("Exception thrown during login: ", e.what());
  }

  return nlohmann::json{{"error", "Login failed."}}.dump();
}

bool Server::UserExists(const std::string& name)
{
  try
  {
    QueryValues values = m_db.select("users", {"id"}, CreateFilter("name", name));
    for (auto value : values)
      std::cout << value.first << " : " << value.second << std::endl;
    return !(values.empty());
  }
  catch(const std::exception& e)
  {
    std::cerr << e.what() << '\n';
  }
   return false;
}

void Server::AddUser(const std::string& name, const std::string& password)
{
  m_db.insert("users", {"name", "password"}, {name, password});
}
