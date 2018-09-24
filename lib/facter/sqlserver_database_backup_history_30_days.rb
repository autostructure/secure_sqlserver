
# sqlserver_database_backup_history_30_days.rb
#
# Dependencies:
# v79083
#
# @return   An array of database backup history (30 days worth by database).
# @example
#
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
require 'sqlserver_client'

Facter.add('sqlserver_database_backup_history_30_days') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT database_name,
CASE type
WHEN 'D' THEN 'Full'
WHEN 'I' THEN 'Differential'
WHEN 'L' THEN 'Log'
ELSE type
END AS backup_type,
is_copy_only,
backup_start_date,
backup_finish_date
FROM msdb.dbo.backupset
WHERE backup_start_date >= dateadd(day, - 30, getdate())
ORDER BY database_name, backup_start_date DESC"

    Puppet.debug "sqlserver_database_backup_history_30_days.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
