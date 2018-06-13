#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver
{

  include ::secure_sqlserver::logon

  # if $::secure_sqlserver::logon::version != 'SQL_2016' {
  if $::secure_sqlserver::logon::version != 'SQL_2016' {
    fail("Unsupported MS SQL Server version detected, found ${::secure_sqlserver::logon::version} instead of SQL_2016.")
  }
  # database STIGs...

  # instance STIGs...
  class { '::secure_sqlserver::stig::v79119': }
  class { '::secure_sqlserver::stig::v79121': }
  class { '::secure_sqlserver::stig::v79123': }
  class { '::secure_sqlserver::stig::v79129': }
}
