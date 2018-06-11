# This class manages DISA STIG vulnerability: V-79119
# SQL Server must limit the number of concurrent sessions to an organization-defined
# number per user for all accounts and/or account types.
#
class secure_sqlserver::stig::v79119 (
  Boolean $enforced = false,
) {

  # Make sure to use the renamed SA account here.
  $sa = 'sa'
  $db = 'master'
  $limit = 1000
  $sql_check = 'SELECT name FROM master.sys.server_triggers;'
  $sql_trigger = "CREATE TRIGGER SQL_STIG_v79119_Connection_Limit
ON ALL SERVER WITH EXECUTE AS '${sa}'
FOR LOGON
AS
BEGIN
IF (SELECT COUNT(1)
FROM sys.dm_exec_sessions
WHERE is_user_process = 1
And original_login_name = ORIGINAL_LOGIN()
) > ${limit}
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
