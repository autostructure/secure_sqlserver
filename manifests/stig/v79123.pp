# This class manages DISA STIG vulnerability: V-79123
# *** RESTART REQ'D ***
# SQL Server must be configured to utilize the most-secure authentication method available.
#
class secure_sqlserver::stig::v79123 (
  Boolean $enforced = false,
) {

  $port = 1
  $svc_acct = 'WIN-OKVLNTQGMS4\Administrator'
  $cmd_setspn_fqdn = "setspn -S MSSQLSvc/${fqdn} ${svc_acct}"
  $cmd_setspn_port = "setspn -S MSSQLSvc/${fqdn}:${port} ${svc_acct}"

  exec { 'v79123_setspn_fqdn':
    path    => 'C:\Windows\system32',
    command => $cmd_setspn_fqdn,
  }

  exec { 'v79123_setspn_port':
    path    => 'C:\Windows\system32',
    command => $cmd_setspn_port,
  }

}
