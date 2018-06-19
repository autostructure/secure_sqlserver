#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver
{

  include ::secure_sqlserver::logon
  include ::secure_sqlserver::version_check
  include ::secure_sqlserver::secure_instance
  include ::secure_sqlserver::secure_database

  Class['::secure_sqlserver::logon']
    -> Class['::secure_sqlserver::version_check']
    -> Class['::secure_sqlserver::secure_instance']
    -> Class['::secure_sqlserver::secure_database']

  #Package['tiny_tds']
  #  -> Class['::secure_sqlserver::logon']
  #  -> Class['::secure_sqlserver::version_check']
  #  -> Class['::secure_sqlserver::secure_instance']
  #  -> Class['::secure_sqlserver::secure_database']

}
