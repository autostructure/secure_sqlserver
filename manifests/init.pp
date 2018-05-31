#
# This module secures Microsoft SQL Server
#
class secure_sqlserver
{
  class { '::secure_sqlserver::stig::v67357': }
  class { '::secure_sqlserver::stig::v67361': }
}
