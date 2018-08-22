# v79073.pp
#
# This class manages DISA STIG vulnerability: V-79073
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM)
# to select which auditable events are to be audited.
#
define secure_sqlserver::stig::v79073 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

  

  }

}
