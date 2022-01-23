#include "util.hpp"

std::string ReadFile(const std::string& path)
{
  const std::ifstream     file_stream{path};
        std::stringstream ss{};
  ss << file_stream.rdbuf();

  return ss.str();
}

void SaveToken(const std::string& token, const std::string& name)
{
  const std::string path{"tokens/" + name};
  std::ofstream     out{path.c_str(), (std::ios::trunc | std::ios::out | std::ios::binary)};
  out << token;
}
