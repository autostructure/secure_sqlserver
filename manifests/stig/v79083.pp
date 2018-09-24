# v79083
#
#
#
###################################################################################
# STIG Info...
###################################################################################
# USE [master]
# GO
#
# SELECT name, recovery_model_desc
# FROM sys.databases
# ORDER BY name
#
# If the recovery model description does not match the documented recovery model, this is a finding.
#
# Review the jobs set up to implement the backup plan. If they are absent, this is a finding.
#
# Check the history of the backups by running the following query. It checks the last 30 days of backups by database.
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

define secure_sqlserver::stig::v79083 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    $roles_and_users = $facts['']


  }
}
