#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver
{

  class { '::secure_sqlserver::logon': }
  -> class { '::secure_sqlserver::version_check': }

  # database STIGs...
  # class { '::secure_sqlserver::stig::v79061': }

  # instance STIGs...
  class { '::secure_sqlserver::stig::v79119': }
  class { '::secure_sqlserver::stig::v79121': }
  class { '::secure_sqlserver::stig::v79123': }
  class { '::secure_sqlserver::stig::v79129': }
}
