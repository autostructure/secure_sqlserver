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

    $temporal_tables = lookup('secure_sqlserver::temporal_tables')
    $existing_temporals = facts$['sqlserver_temporal_tables']

  }
}
