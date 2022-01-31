#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <httplib.h>
#include "db.hpp"

class Server
{
public:
Server(int argc, char** argv);

private:
bool        Register(const std::string& username, const std::string& password);
std::string Login(const std::string& username, const std::string& password);
void        Init();
bool        UserExists(const std::string& name);
void        AddUser(const std::string& name, const std::string& password);

httplib::Server m_server;
Database::KDB   m_db;
std::string     m_pr_key;
std::string     m_pb_key;
};

