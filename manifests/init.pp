#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver
{

  if $::secure_sqlserver::logon::version != 'SQL_2016' {
    fail("Unsupported operating system (${facts['operatingsystemmajrelease']}) detected.")
  }
  # database STIGs...

  # instance STIGs...
  class { '::secure_sqlserver::stig::v79119': }
  class { '::secure_sqlserver::stig::v79121': }
  class { '::secure_sqlserver::stig::v79123': }
  class { '::secure_sqlserver::stig::v79129': }
}
