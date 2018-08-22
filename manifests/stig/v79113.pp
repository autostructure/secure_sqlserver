# v79113.pp
#
# This class manages DISA STIG vulnerability: V-79113
# SQL Server must use NSA-approved cryptography to protect classified information
# in accordance with the data owners requirements.
#
define secure_sqlserver::stig::v79113 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {



  }

}
