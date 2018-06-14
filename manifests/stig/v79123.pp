# This class manages DISA STIG vulnerability: V-79123
# SQL Server must be configured to utilize the most-secure authentication method available.
# *** RESTART REQ'D ***
#
class secure_sqlserver::stig::v79123 (
  Boolean $enforced = false,
) {

  $fqdn = $facts['fqdn']
  $port = $::secure_sqlserver::logon::port
  $netbios_user = $::secure_sqlserver::logon::netbios_user
  $cmd_setspn_fqdn = "setspn -S MSSQLSvc/${fqdn} '${netbios_user}'"
  $cmd_setspn_port = "setspn -S MSSQLSvc/${fqdn}:${port} '${netbios_user}'"

  exec { 'v79123_setspn_fqdn':
    path    => 'C:\Windows\system32',
    command => $cmd_setspn_fqdn,
  }

  exec { 'v79123_setspn_port':
    path    => 'C:\Windows\system32',
    command => $cmd_setspn_port,
  }

}
