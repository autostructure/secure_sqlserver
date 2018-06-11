# This class manages DISA STIG vulnerability: V-79129
# SQL Server must protect against a user falsely repudiating by ensuring the
# NT AUTHORITY SYSTEM account is not used for administration.
#
class secure_sqlserver::stig::v79129 (
  Boolean $enforced = false,
) {

  # make sure that is the only role.
  $server_role = 'Public'
  $system_user = 'NT AUTHORITY\SYSTEM'

  # Resource to connect to the DB instance
  #sqlserver::config { 'MSSQLSERVER':
  #  admin_login_type => 'WINDOWS_LOGIN',
  #}

  #sqlserver::role { 'sysadmin':
  #  ensure   => 'present',
  #  instance => 'MSSQLSERVER',
  #  type     => 'SERVER',
  #  members  => [$local_dba_group_netbios_name, $facts['id']],
  #}

  #sqlserver_tsql{ 'Always running':
  #  instance => 'MSSQLSERVER',
  #  command  => 'EXEC notified_executor()',
  #}

}
