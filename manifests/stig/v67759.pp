# This class manages V-67759
# SQL Server authentication and identity management must be integrated with an
# organization-level authentication/access mechanism providing account management
# and automation for all users, groups, roles, and any other principals.
# RESTART REQ'D
class secure_sqlserver::stig::v67759 (
  Boolean $enforced = false,
) {

  # this requires a restart to take effect...
  registry::value { 'v67759':
    key   => 'HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer',
    value => 'LoginMode',
    type  => 'dword',
    data  => '0x00000001',
  }

}
