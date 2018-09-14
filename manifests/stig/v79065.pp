# v79065.pp
#
# This class manages DISA STIG vulnerability: V-79065
# SQL Server must enforce approved authorizations for logical access to
# information and system resources in accordance with applicable access control policies.
#
define secure_sqlserver::stig::v79065 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  file { file1:
    ensure => true,
    path => 'C:\Windows\Temp\no-title-test-delete-me.txt'
  }

}
