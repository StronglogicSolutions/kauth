#include "db.hpp"

DatabaseConfiguration GetConfig()
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
