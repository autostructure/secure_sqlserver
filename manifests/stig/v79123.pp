# v79123.pp
#
# This class manages DISA STIG vulnerability: V-79123
# SQL Server must be configured to utilize the most-secure authentication method available.
#
# *** REBOOT REQ'D ***
# *** RESTART REQ'D ***
#
class secure_sqlserver::stig::v79123 (
  String  $port,
  String  $user,
  Boolean $enforced = false,
) {
  if $enforced {
    $fqdn = $facts['fqdn']
    $cmd_setspn_fqdn = "setspn -S MSSQLSvc/${fqdn} '${user}'"
    $cmd_setspn_port = "setspn -S MSSQLSvc/${fqdn}:${port} '${user}'"

    exec { 'v79123_setspn_fqdn':
      path    => 'C:\\Windows\\system32',
      command => $cmd_setspn_fqdn,
    }

    exec { 'v79123_setspn_port':
      path    => 'C:\\Windows\\system32',
      command => $cmd_setspn_port,
    }
  }
}
