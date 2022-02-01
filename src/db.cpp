#include "db.hpp"

static DatabaseConfiguration GetConfig()
{
  return {
    DatabaseCredentials{
      "", "", ""},
      "",
      ""};
}

Database::KDB GetDatabase()
{
  return Database::KDB{GetConfig()};
}
