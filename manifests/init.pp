#
# This module secures Microsoft SQL Server 2016
# @Usage
# class { '::secure_sqlserver': }
#
class secure_sqlserver (
  String $svc_acct,
) {

  class { '::secure_sqlserver::controller':
    svc_acct => $svc_acct,
  }

}
