# v79107.pp
#
# Execution of stored procedures and functions that utilize execute as must be restricted to necessary cases only.
#
define secure_sqlserver::stig::v79107 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {
    notify { "v79107: ${instance}\\${database}: v79107 called.":
      loglevel => notice,
    }
  }

}
