# This class manages DISA STIG vulnerability: V-79119
# SQL Server must limit the number of concurrent sessions to an organization-defined
# number per user for all accounts and/or account types.
#
class secure_sqlserver::stig::v79119 (
  Boolean $enforced = false,
) {

  $netbios_user = "${facts['domain']}\\${facts['id']}"

  sqlserver::config { 'MSSQLSERVER':
    admin_login_type => 'WINDOWS_LOGIN',
  }

  # sqlserver::login { $netbios_user :
  #   login_type  => 'WINDOWS_LOGIN',
  # }

  # Make sure to use the renamed SA account here.
  $sa = 'sa'
  $db = 'MSSQLSERVER'
  $trigger_name = 'SQL_STIG_V79119_CONNECTION_LIMIT'
  $connection_limit = 1000
  # $sql_check = 'SELECT name FROM master.sys.server_triggers;'
  $sql_check = "IF (SELECT COUNT(*) FROM master.sys.server_triggers WHERE name='${trigger_name}') = 0 THROW 50000, '', 10"
  $sql_trigger = "CREATE TRIGGER ${trigger_name}
ON ALL SERVER WITH EXECUTE AS '${sa}'
FOR LOGON
AS
BEGIN
IF (SELECT COUNT(1)
FROM sys.dm_exec_sessions
WHERE is_user_process = 1
And original_login_name = ORIGINAL_LOGIN()
) > ${connection_limit}
BEGIN
PRINT 'The login [' + ORIGINAL_LOGIN() + '] has exceeded the concurrent session limit.'
ROLLBACK;
END
END;"

  sqlserver_tsql{ 'create logon trigger to limit concurrent sessions':
    instance => $db,
    command  => $sql_trigger,
    onlyif   => $sql_check,
  }

}
