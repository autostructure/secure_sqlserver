# This class manages DISA STIG vulnerability: V-79
#
class secure_sqlserver::stig::v79 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {

  ::secure_sqlserver::log {'DoD STIG vulnerability v79xxx was skipped, it requires manual intervention.':}

}
