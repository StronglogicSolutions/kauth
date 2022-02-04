#pragma once

#include <sstream>
#include <fstream>
#include <iostream>

std::string ReadFile (const std::string& path);
void        SaveToken(const std::string& token, const std::string& name);

template<typename... Args>
static void log(Args... args)
{
  for (const auto& s : {args...})
    std::cout << s;
  std::cout << std::endl;
}
