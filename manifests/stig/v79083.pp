# v79083
#
# In the event of a system failure, hardware loss or disk failure,
# SQL Server must be able to restore necessary databases with least disruption to mission processes.
#
###################################################################################
# STIG Info...
###################################################################################
# Run the following to determine Recovery Model:
#
# USE [master]
# GO
#
# SELECT name, recovery_model_desc
# FROM sys.databases
# ORDER BY name
#
# Check the history of the backups by running the following query.
# It checks the last 30 days of backups by database.
#
# USE [msdb]
# GO
#
# SELECT database_name,
# CASE type
# WHEN 'D' THEN 'Full'
# WHEN 'I' THEN 'Differential'
# WHEN 'L' THEN 'Log'
# ELSE type
# END AS backup_type,
# is_copy_only,
# backup_start_date, backup_finish_date
# FROM dbo.backupset
# WHERE backup_start_date >= dateadd(day, - 30, getdate())
# ORDER BY database_name, backup_start_date DESC
###################################################################################
#
define secure_sqlserver::stig::v79083 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    $recovery_models = $facts['sqlserver_database_backup_recovery_models']

    unless empty($recovery_models) {

      $recovery_models.each |$model_hash| {

        $model = $model_hash['recovery_model']
        $db = $model_hash['database_name']

        if downcase($db) == downcase($database) {
          unless empty($model) {
            notify { "v79083: ${instance}\\${database}: recovery_model = ${model}":
              loglevel => notice,
            }
          } else {
            notify { "v79083: ${instance}\\${database}: recovery_models empty.":
              loglevel => notice,
            }
          }
        }

      }
    }

    # $recovery_models.each |$model_hash| {
    #
    #   $model = $model_hash['recovery_model']
    #
    #   unless empty($model) {
    #
    #     $sql = ""
    #     ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql}": }
    #     sqlserver_tsql{ "v79083_set_recovery_model_for_${instance}_${database}":
    #       instance => $instance,
    #       database => $database,
    #       command  => $sql,
    #       require  => Sqlserver::Config[$instance],
    #     }
    #
    #     $sql = ""
    #     ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql}": }
    #     sqlserver_tsql{ "v79083_create_backup_schedule_for_${instance}_${database}":
    #       instance => $instance,
    #       database => $database,
    #       command  => $sql,
    #       require  => Sqlserver::Config[$instance],
    #     }
    #
    # }

  }
}
