# v79067.pp
#
# This class manages DISA STIG vulnerability: V-79067
# SQL Server must protect against a user falsely repudiating by ensuring
#
# U    WINDOWS_LOGIN
# G    GROUP
#
class secure_sqlserver::stig::v79067 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    $drop_users = []

    $drop_users = $facts['sqlserver_shared_accounts_detail']
    $drop_users.each |$potential_dropped_user| {

      $sql_dcl = "DROP USER IF EXISTS ${potential_dropped_user}"

      ::secure_sqlserver::log { "v79067_sql_dcl = \n${sql_dcl}": }

      sqlserver_tsql{ "v79067_drop_user_${database}_${username}":
        instance => $instance,
        command  => $sql_dcl,
        require  => Sqlserver::Config[$instance],
      }

    }



    # v79131
    $shared_accounts = $facts['sqlserver_shared_accounts']
    unless $shared_accounts == undef or $shared_accounts == '' {
      $shared_accounts.each |$drop_user| {
        $sql_dcl = "DROP USER '${drop_user}';"
        ::secure_sqlserver::log { "v79131_sql_dcl = \n${sql_dcl}": }
        sqlserver_tsql{ "remove_shared_account_${drop_user}":
          instance => $instance,
          command  => $sql_dcl,
          require  => Sqlserver::Config[$instance],
        }
      }
    }




  }
}
