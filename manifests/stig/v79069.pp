# v79069.pp
#
# SQL Server must protect against a user falsely repudiating by use of system-versioned tables (Temporal Tables).
#
define secure_sqlserver::stig::v79069 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {
    notify { "v79069: ${instance}\\${database}: v79069 called.":
      loglevel => notice,
    }
  }

}
