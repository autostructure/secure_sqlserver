# v79177.pp
# Access to xp_cmdshell must be disabled, unless specifically required and approved.
#
class secure_sqlserver::stig::v79177 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  if $enforced {

    $sql = "EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;"

    sqlserver_tsql{ 'v79177-tsql-disable-xpcmdshell':
      instance => $instance,
      command  => $sql,
      require  => Sqlserver::Config[$instance],
    }

  }
}
