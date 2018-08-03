# This class manages DISA STIG vulnerability: V-79071
# SQL Server must protect against a user falsely repudiating by ensuring databases
# are not in a trust relationship.
#
class secure_sqlserver::stig::v79071 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    $sql_dcl = "ALTER DATABASE ${database} SET TRUSTWORTHY OFF"

    ::secure_sqlserver::log { "v79061_sql_dcl = \n${sql_dcl}": }

    sqlserver_tsql{ "drop_user_${database}_${username}":
      instance => $instance,
      command  => $sql_dcl,
      require  => Sqlserver::Config[$instance],
    }

  }

}
