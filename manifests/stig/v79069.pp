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

    $desired_temporal_tables = lookup('secure_sqlserver::temporal_tables')
    $existing_temporal_tables = $facts['sqlserver_temporal_tables'][$database]

    unless empty($desired_temporal_tables) {

      $desired_temporal_tables.each |$temporal_table| {
        # check if desired table is already set up...
        unless empty($existing_temporal_tables) or $temporal_table in $existing_temporal_tables {
          $sql = "ALTER TABLE ${temporal_table}
          ADD PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime),
          SysStartTime datetime2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT GETUTCDATE(),
          SysEndTime datetime2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.99999999');"

          ::secure_sqlserver::log { "v79069: calling tsql module for, ${instance}\\${database}, temporal table, ${temporal_table}, using sql = \n${sql}": }

          sqlserver_tsql{ "v79069_make_table_temporal_${temporal_table}_for_${instance}_${database}":
            instance => $instance,
            database => $database,
            command  => $sql,
            require  => Sqlserver::Config[$instance],
          }

          # Enable system versioning with 1-year retention for historical data.
          $sql2 = "ALTER TABLE ${temporal_table} SET (SYSTEM_VERSIONING = ON (HISTORY_RETENTION_PERIOD = 1 YEAR));"

          ::secure_sqlserver::log { "v79069: calling tsql module for, ${instance}\\${database}, temporal table retention set on , ${temporal_table}, using sql = \n${sql2}": }

          sqlserver_tsql{ "v79069_set_table_temporal_retention_${temporal_table}_for_${instance}_${database}":
            instance => $instance,
            database => $database,
            command  => $sql2,
            require  => Sqlserver::Config[$instance],
          }

        }
      }

    }

  }
}
