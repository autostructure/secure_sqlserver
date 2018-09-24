# v79105.pp
#
# SQL Server must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.
#
define secure_sqlserver::stig::v79105 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {
    notify { "v79105: ${instance}\\${database}: v79105 called.":
      loglevel => notice,
    }
  }

}
