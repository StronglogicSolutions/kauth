#pragma once

#include <sstream>
#include <fstream>

std::string ReadFile (const std::string& path);
void        SaveToken(const std::string& token, const std::string& name);
