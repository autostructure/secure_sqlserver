#
# This module secures Microsoft SQL Server 2016
#
class secure_sqlserver
{

  package { 'tiny_tds':
    ensure   => 'installed',
    provider => 'gem',
  }

  Class['secure_sqlserver::logon']
    -> Class['secure_sqlserver::version_check']
    -> Class['secure_sqlserver::secure_instance']
    -> Class['secure_sqlserver::secure_database']

  # class { '::secure_sqlserver::logon': }
  #   -> class { '::secure_sqlserver::version_check': }
  #   -> class { '::secure_sqlserver::secure_instance': }
  #   -> class { '::secure_sqlserver::secure_database': }

}
