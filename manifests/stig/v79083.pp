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

    notify { "v79083: ${instance}\\${database}: recovery_models['${database}'] = ${recovery_models['${database}']}": }

    # $sql = ""
    # notify { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql}": }


  }
}
