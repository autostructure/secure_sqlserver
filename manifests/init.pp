#
# This module secures Microsoft SQL Server
#
class secure_sqlserver
{
  # database STIGs...
  class { '::secure_sqlserver::stig::v67357': }
  class { '::secure_sqlserver::stig::v67361': }

  # instance STIGs...
  class { '::secure_sqlserver::stig::v67387': }
}
