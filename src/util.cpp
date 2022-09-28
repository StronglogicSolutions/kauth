#include "util.hpp"

std::string ReadFile(const std::string& path)
{
  const std::ifstream     file_stream{path};
        std::stringstream ss{};
  ss << file_stream.rdbuf();

  return ss.str();
}

void SaveTokens(const std::string& token, const std::string& refresh, const std::string& name)
{
  const std::string path   {"tokens/" + name};
  const std::string rf_path{path + "_refresh"};
  std::ofstream     out{path, (std::ios::trunc | std::ios::out | std::ios::binary)};
  out << token;
  out.close();
  out = std::ofstream{rf_path, (std::ios::trunc | std::ios::out | std::ios::binary)};
  out << refresh;
}
