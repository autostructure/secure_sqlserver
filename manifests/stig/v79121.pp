# This class manages DISA STIG vulnerability: V-79121
# SQL Server must integrate with an organization-level authentication/access mechanism
# providing account management and automation for all users, groups, roles, and any other principals.
# *** RESTART REQ'D ***
#
class secure_sqlserver::stig::v79121 (
  Boolean $enforced = false,
  Optional[String] $instance = 'MSSQLSERVER',
) {

  # this requires a restart to take effect...
  registry::value { 'v79121':
    key   => 'HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer',
    value => 'LoginMode',
    type  => 'dword',
    data  => '0x00000002',
  }

}
