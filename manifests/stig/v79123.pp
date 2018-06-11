# This class manages DISA STIG vulnerability: V-79123
# SQL Server must be configured to utilize the most-secure authentication method available.
# *** RESTART REQ'D ***
#
class secure_sqlserver::stig::v79123 (
  Boolean $enforced = false,
) {

  $fqdn = $facts['fqdn']
  $port = 1433
  $svc_acct = "${facts['domain']}\${facts['id']}"
  secure_sqlserver::log { $svc_acct: }
  #$svc_acct = 'WIN-OKVLNTQGMS4\Administrator'
  #$svc_acct = 'jeff-win-2012-sqlserver\Administrator'
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
