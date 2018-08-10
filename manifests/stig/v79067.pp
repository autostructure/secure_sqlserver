# v79067.pp
#
# This class manages DISA STIG vulnerability: V-79067
# SQL Server must protect against a user falsely repudiating by ensuring
# only clearly unique Active Directory user accounts can connect to the database.
#
# U    WINDOWS_LOGIN
# G    GROUP
#
define secure_sqlserver::stig::v79067 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {
    $shared_accounts = $facts['sqlserver_shared_database_accounts']
    unless $shared_accounts == undef or empty($shared_accounts) {
      $shared_accounts.each |$drop_user| {
        $sql = "DROP USER IF EXISTS ${drop_user}"
        ::secure_sqlserver::log { "v79067 sql = \n${sql}": }
        sqlserver_tsql{ "v79067_drop_user_${database}_${username}":
          instance => $instance,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      }
    }
  }
}
