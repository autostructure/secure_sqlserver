# This class manages DISA STIG vulnerability: V-79071
# SQL Server must protect against a user falsely repudiating by ensuring databases
# are not in a trust relationship.
#
# NOTE:
# If the database is MSDB, trustworthy is required to be enabled and therefore, this is not a finding.
#
define secure_sqlserver::stig::v79071 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    $is_trustworthy_disabled = false

    $db_array = $facts['sqlserver_databases_trustworthy_property']
    $db_array.each |$db_hash| {
      if downcase($db_hash['database_name']) == downcase($database) {
        $is_trustworthy_disabled = $db_hash['is_trustworthy_on']
      }
    }

    # If the database is MSDB, trustworthy is required to be enabled...
    unless downcase($database) == 'msdb' or $is_trustworthy_disabled {
      $sql_dcl = "ALTER DATABASE ${database} SET TRUSTWORTHY OFF"

      ::secure_sqlserver::log { "v79071_sql_dcl = \n${sql_dcl}": }

      sqlserver_tsql{ "v79071_alter_db_disable_trustworthy_${database}":
        instance => $instance,
        command  => $sql_dcl,
        require  => Sqlserver::Config[$instance],
      }
    }

  }

}
