#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver::version_check ()
{

  # if $::secure_sqlserver::logon::version != 'SQL_2016' {
  if $::secure_sqlserver::logon::version != 'SQL_2016' {
    fail("Unsupported MS SQL Server version detected, found ${::secure_sqlserver::logon::version} instead of SQL_2016.")
  }

}
