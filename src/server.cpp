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

using n_json = nlohmann::json;
auto JSON    = [](const auto& key, const auto& val) { return n_json{{key, val}}.dump(); };

static void PrintClaims(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded)
{
  auto claim = decoded.get_payload_claim("user");
  auto user  = claim.as_string();               std::cout << "User: " << user  <<                       std::endl;
  for (auto&& e : decoded.get_payload_claims()) std::cout << e.first  << " = " << e.second.to_json() << std::endl;
}

bool ValidateToken(std::string token, std::string name, std::string priv, std::string pub)
{
  auto Expired        = [](const jwt::date&   date) { return std::chrono::system_clock::now() > date;          };

  using Verifier = jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson>;
  static const Verifier    verifier    = jwt::verify()
    .allow_algorithm(jwt::algorithm::es256k(pub, priv, "", ""))
    .with_issuer    ("kiq");

  try
  {
    const auto decoded = jwt::decode(token);
    verifier.verify(decoded);

    if (decoded.get_payload_claim("user").as_string() != name)

      log("Token does not belong to user");
    else
    if (Expired(decoded.get_expires_at()))
      log("Token has expired");
    else
    {
      log("Token valid for {}", name.c_str());
      return true;
    }
  }
  catch(const std::exception& e)
  {
    log("Exception thrown while validating token: {}", e.what());
  }
  return false;
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

std::chrono::seconds get_expiry(bool refresh = false)
{
  return (refresh) ? std::chrono::seconds(2592000) : std::chrono::seconds(86400);
}

static jwt::traits::kazuho_picojson::string_type
CreateToken(const std::string_view& username,
            const std::string& priv_key,
            const std::string& pub_key,
            bool               refresh = false)
{
  return jwt::create()
              .set_issuer       ("kiq")
              .set_type         ("JWT")
              .set_id           ("kiq_auth")
              .set_issued_at    (std::chrono::system_clock::now())
              .set_expires_at   (std::chrono::system_clock::now() + get_expiry(refresh))
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
  auto GetJSON = [](const auto& t) { return(t.size()) ? JSON("token", t) : JSON("error", "Login failed"); };

  m_server.Get("/login", [this, &GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    std::string name, pass;

    if (req.has_param("name"))     name = req.get_param_value("name");
    if (req.has_param("password")) pass = req.get_param_value("password");

    res.set_content(Login(name, pass), APPLICATION_JSON);
  });

  m_server.Get("/register", [this, &GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    std::string name, pass, key;

    if (req.has_param("name"))     name = req.get_param_value("name");
    if (req.has_param("password")) pass = req.get_param_value("password");
    if (req.has_param("key"))      key  = req.get_param_value("key");

    res.set_content((Register(name, pass, key)) ? "Created" : "Failed", HTML_MARKUP);
  });

  m_server.Get("/refresh", [this, &GetJSON](const httplib::Request& req, httplib::Response& res)
  {
    using json = nlohmann::json;
    std::string content;
    if (req.has_param("refresh") || req.has_param("name"))
    {
      const auto refresh = req.get_param_value("refresh");
      const auto name    = req.get_param_value("name");
      if (ValidateToken(refresh, name, m_pr_key, m_pb_key))
      {
        const auto token = CreateToken(req.get_param_value("name"), m_pr_key, m_pb_key);
        SaveTokens(token, refresh, name);
        content = json{{"token", token}};
      }
    }
    else
      content = json{{"error", "refresh failed"}};

    res.set_content(content, APPLICATION_JSON);
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
  auto GetJSON = [](const auto& t, const auto& r)
  {
    return(t.size() && r.size()) ?
      nlohmann::json{{"token", t}, {"refresh", r}}.dump() :
      JSON("error", "Login failed"); };
  log("Login attempt by ", username.c_str(), " with pass ", password.c_str());

  try
  {
    if (username.size() && password.size() &&
        BCrypt::validatePassword(password, BCrypt::generateHash(password)))
    {
      log("Login validated");
      static const bool is_refresh = true;
      auto token   = CreateToken(username, m_pr_key, m_pb_key);
      auto refresh = CreateToken(username, m_pr_key, m_pb_key, is_refresh);

      if (VerifyToken(token,   m_pr_key, m_pb_key) &&
          VerifyToken(refresh, m_pr_key, m_pb_key))
      {
        SaveTokens(token, refresh, username);
        log("Returning tokens");
        return GetJSON(token, refresh);
      }
    }
  }
  catch(const std::exception& e)
  {
    log("Exception thrown during login: ", e.what());
  }

  return "";
}

bool Server::UserExists(const std::string& name)
{
  return (m_db.select("users", {"id"}, CreateFilter("name", name)).size() > 0);
}

void Server::AddUser(const std::string& name, const std::string& password)
{
  m_db.insert("users", {"name", "password"}, {name, password});
}
