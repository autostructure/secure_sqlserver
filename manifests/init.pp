#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver
{
  # database STIGs...

  # instance STIGs...
  class { '::secure_sqlserver::stig::v79119': }
  class { '::secure_sqlserver::stig::v79121': }
  class { '::secure_sqlserver::stig::v79123': }
}
