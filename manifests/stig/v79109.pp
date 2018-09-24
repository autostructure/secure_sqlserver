# v79109.pp
#
# SQL Server must prohibit user installation of logic modules
# (stored procedures, functions, triggers, views, etc.) without explicit privileged status.
#
define secure_sqlserver::stig::v79109 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {
    notify { "v79109: ${instance}\\${database}: v79109 called.":
      loglevel => notice,
    }
  }

}
