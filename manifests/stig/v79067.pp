# v79067.pp
#
# This class manages DISA STIG vulnerability: V-79067
# SQL Server must protect against a user falsely repudiating by ensuring
# only clearly unique Active Directory user accounts can connect to the database.
#
# NOTE: Not checking for the output of this command to determine if account is local:
#       ([ADSISearcher]"(&(!ObjectCategory=Computer)(Name=<name>))").FindAll()
# NOTE:  USE fact "sqlserver_shared_database_accounts_detail", it includes
#        the powershell check code, but we don't know how the output is returned yet.
#
define secure_sqlserver::stig::v79067 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
  Array         $approved_shared_accounts,
) {

  if $enforced {

    # yaml file contains approved_users, skip the DROP for any in the list...
    $approved_users = $approved_shared_accounts
    $remote_accounts = $facts['sqlserver_remote_database_accounts']

    unless $remote_accounts == undef or empty($remote_accounts) {
      $remote_accounts.each |$drop_user| {
        unless $drop_user in $approved_users {
          $sql = "DROP USER IF EXISTS ${drop_user}"
          ::secure_sqlserver::log { "v79067 sql = \n${sql}": }
          sqlserver_tsql{ "v79067_drop_shared_user_${instance}_${database}_${drop_user}":
            instance => $instance,
            database => $database,
            command  => $sql,
            require  => Sqlserver::Config[$instance],
          }
        }
      }
    }

  }

}
