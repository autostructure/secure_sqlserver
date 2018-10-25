# v79083
#
# In the event of a system failure, hardware loss or disk failure,
# SQL Server must be able to restore necessary databases with least disruption to mission processes.
#
# Recovery Types
# --------------
# SIMPLE        Can recover only to the end of a backup. No log backups.
# FULL          Can recover to a specific point in time.* Requires log backups.
# BULK_LOGGED   Can recover to the end of any backup. Point-in-time recovery is not supported. Requires log backups.
#
# * assuming that your backups are complete up to that point in time.
#
# Backup Types
# ------------
# 1. Full backups
# 2. Differential backups
# 3. File backups
# 4. Filegroup backups
# 5. Partial backups
# 6. Copy-Only backups
# 7. Mirror backups
# 8. Transaction log backups
#
#
# sp_add_schedule @freq_type
# ==========================
#     1	  Once
#     4	  Daily
#     8	  Weekly
#     16	Monthly
#     32	Monthly, relative to freq_interval
#     64	Run when SQLServerAgent service starts
#     128	Run when the computer is idle
#
# sp_add_schedule @freq_type
# ==========================
# freq_type / Effect on freq_interval
#     1   (once) freq_interval is unused.
#     4   (daily) Every freq_interval days.
#     8   (weekly) freq_interval is one or more of the following (combined with an OR logical operator):
#         1 = Sunday
#         2 = Monday
#         4 = Tuesday
#         8 = Wednesday
#         16 = Thursday
#         32 = Friday
#         64 = Saturday
#     16  (monthly)	On the freq_interval day of the month.
#     32  (monthly relative)	freq_interval is one of the following:
#         1 = Sunday
#         2 = Monday
#         3 = Tuesday
#         4 = Wednesday
#         5 = Thursday
#         6 = Friday
#         7 = Saturday
#         8 = Day
#         9 = Weekday
#         10 = Weekend day
#     64  (when SQLServerAgent service starts)	freq_interval is unused.
#     128 freq_interval is unused.
#
#
# Fact 'sqlserver_database_backup_recovery_models' example...
#
# [ {
#   "database_name" : "FN_Test",
#   "recovery_model" : "SIMPLE"
# }, {
#   "database_name" : "GST_Test",
#   "recovery_model" : "FULL"
# }, {
#   "database_name" : "master",
#   "recovery_model" : "SIMPLE"
# }, {
#   "database_name" : "MFS_Test",
#   "recovery_model" : "FULL"
# }, {
#   "database_name" : "model",
#   "recovery_model" : "FULL"
# }, {
#   "database_name" : "msdb",
#   "recovery_model" : "SIMPLE"
# }, {
#   "database_name" : "tempdb",
#   "recovery_model" : "SIMPLE"
# } ]
#
define secure_sqlserver::stig::v79083 (
  Hash          $backup_plan,
  Hash          $backup_recovery_model_settings,
  String[1,16]  $instance,
  String        $database,
  Boolean       $enforced = false,
) {
  if $enforced {
    $target_recovery_model = upcase($backup_recovery_model_settings[$database])

    $recovery_models = $facts['sqlserver_database_backup_recovery_models']

    unless empty($recovery_models) {
      $recovery_models.each |$model_hash| {
        $db = $model_hash['database_name']

        if downcase($db) == downcase($database) {
          unless empty($model_hash['recovery_model']) {
            ##TODO:
            # is this block used to set the model from hiera setting?
            # is that wise to do so?
            $model = upcase($model_hash['recovery_model'])
            if $model != $target_recovery_model and !empty($target_recovery_model) {
              $sql = "ALTER DATABASE ${database} SET RECOVERY ${target_recovery_model}"
              ::secure_sqlserver::log { "v79083: ${instance}\\${database}: changing recovery model from ${model} to ${target_recovery_model}, sql = \n${sql}": } #lint:ignore:140chars
              sqlserver_tsql{ "v79083_set_recovery_model_for_${instance}_${database}":
                instance => $instance,
                database => $database,
                command  => $sql,
                require  => Sqlserver::Config[$instance],
              }
            }
          } else {
            ##TODO:
            # if model empty, set backup to what?  Something from hiera?
            notify { "v79083: ${instance}\\${database}: recovery_models empty.":
              loglevel => notice,
            }
            $sql = "ALTER DATABASE ${database} SET RECOVERY FULL"
            ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using DEFAULT BACKUP RECOVER (FULL), with sql = \n${sql}": } #lint:ignore:140chars
            sqlserver_tsql{ "v79083_set_missing_recovery_model_for_${instance}_${database}":
              instance => $instance,
              database => $database,
              command  => $sql,
              require  => Sqlserver::Config[$instance],
            }
          }
        }

      }

    }

    # Create Backup Schedule...

    # create backup command
    # create job
    # create job steps (tasks, where backup commands are run)
    # create schedule
    # attach job to schedule

    if downcase($server_facts['environment']) == 'production' {

      # Object names...
      $db = upcase($database)
      $job_name = "STIG_JOB_V79083_BACKUP_${db}"
      $schedule_name = "STIG_JOB_V79083_SCHED_${db}"
      $step_name_full = "Full database backup for ${database}."
      $step_name_diff = "Differential database backup for ${database}."
      $step_name_logs = "Backup database logs for ${database}."

      # Hiera lookups...
      $backup_plans = $backup_plan

      unless empty($backup_plans[$database]) {
        $backup_plan_desc = $backup_plans[$database]['description']
        $backup_plan_disk = $backup_plans[$database]['disk']
        $backup_plan_diff = $backup_plans[$database]['diff']
        $backup_plan_logs = $backup_plans[$database]['log']

        $sql_full_backup = "BACKUP DATABASE ${database} TO DISK = ''${backup_plan_disk}'' WITH CHECKSUM, DESCRIPTION = '${backup_plan_desc}'"
        $sql_diff_backup = "BACKUP DATABASE ${database} TO DISK = ''${backup_plan_diff}'' WITH DIFFERENTIAL, CHECKSUM, DESCRIPTION = '${backup_plan_desc}'"
        $sql_logs_backup = "BACKUP LOG ${database} TO DISK = ''${backup_plan_logs}'' WITH CHECKSUM, DESCRIPTION = '${backup_plan_desc}'"
        # , DESCRIPTION = '${backup_plan_desc}'

        $sql_add_job_check = "IF (SELECT count(*) FROM msdb.dbo.sysjobs_view WHERE name = '${job_name}') = 0 THROW 50000, 'Missing Backup Job for V-79083.', 10"# lint:ignore:140chars
        $sql_add_job = "EXEC msdb.dbo.sp_add_job @job_name = N'${job_name}' ;"

        $sql_add_job_full_check = "IF (SELECT count(*) FROM msdb.dbo.sysjobs j, msdb.dbo.sysjobsteps js WHERE j.name = '${job_name}' AND js.step_name = '${step_name_full}') = 0 THROW 50000, 'Missing Job Step for V-79083.', 10"# lint:ignore:140chars
        $sql_add_job_full = "EXEC msdb.dbo.sp_add_jobstep
          @job_name = N'${job_name}',
          @step_name = N'${step_name_full}',
          @subsystem = 'TSQL',
          @command = N'${sql_full_backup}',
          @retry_attempts = 5,
          @retry_interval = 5 ;"

        $sql_add_job_diff_check = "IF (SELECT count(*) FROM msdb.dbo.sysjobs j, msdb.dbo.sysjobsteps js WHERE j.name = '${job_name}' AND js.step_name = '${step_name_diff}') = 0 THROW 50000, 'Missing Job Step for V-79083.', 10"#lint:ignore:140chars
        $sql_add_job_diff = "EXEC msdb.dbo.sp_add_jobstep
          @job_name = N'${job_name}',
          @step_name = N'${step_name_diff}',
          @subsystem = 'TSQL',
          @command = N'${$sql_diff_backup}',
          @retry_attempts = 5,
          @retry_interval = 5 ;"

        $sql_add_job_logs_check = "IF (SELECT count(*) FROM msdb.dbo.sysjobs j, msdb.dbo.sysjobsteps js WHERE j.name = '${job_name}' AND js.step_name = '${step_name_logs}') = 0 THROW 50000, 'Missing Job Step for V-79083.', 10"#lint:ignore:140chars
        $sql_add_job_logs = "EXEC msdb.dbo.sp_add_jobstep
          @job_name = N'${job_name}',
          @step_name = N'${step_name_logs}',
          @subsystem = 'TSQL',
          @command = N'${sql_logs_backup}',
          @retry_attempts = 5,
          @retry_interval = 5 ;"

        $sql_add_sched_check = "IF (SELECT count(*) FROM msdb.dbo.sysschedules s WHERE s.name = '${schedule_name}') = 0 THROW 50000, 'Missing Schedule for V-79083.', 10"#lint:ignore:140chars
        $sql_add_sched = "EXEC msdb.dbo.sp_add_schedule
          @schedule_name = N'${schedule_name}' ,
          @freq_type = 4,
          @freq_interval = 1,
          @active_start_time = 010000 ;"

        $sql_attach_sched_check = "IF (SELECT count(*) FROM msdb.dbo.sysschedules s, msdb.dbo.sysjobs j, msdb.dbo.sysjobschedules js WHERE j.job_id = js.job_id AND s.schedule_id = js.schedule_id AND j.name = '${job_name}' AND s.name = '${schedule_name}') = 0 THROW 50000, 'Unattached Schedule for V-79083.', 10"#lint:ignore:140chars
        $sql_attach_sched = "EXEC msdb.dbo.sp_attach_schedule
          @job_name = N'${job_name}',
          @schedule_name = N'${schedule_name}' ;"

        ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job}": }
        sqlserver_tsql{ "v79083_spawn_job_for_backup_of_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql_add_job,
          onlyif   => $sql_add_job_check,
          require  => Sqlserver::Config[$instance],
        }

        ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_full}": }
        sqlserver_tsql{ "v79083_spawn_job_for_full_backup_of_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql_add_job_full,
          onlyif   => $sql_add_job_full_check,
          require  => Sqlserver::Config[$instance],
        }

        ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_diff}": }
        sqlserver_tsql{ "v79083_spawn_job_for_diff_backup_of_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql_add_job_diff,
          onlyif   => $sql_add_job_diff_check,
          require  => Sqlserver::Config[$instance],
        }

        ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_logs}": }
        sqlserver_tsql{ "v79083_spawn_job_for_log_backup_of_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql_add_job_logs,
          onlyif   => $sql_add_job_logs_check,
          require  => Sqlserver::Config[$instance],
        }

        ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_sched}": }
        sqlserver_tsql{ "v79083_create_schedule_for_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql_add_sched,
          onlyif   => $sql_add_sched_check,
          require  => Sqlserver::Config[$instance],
        }

        ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_attach_sched}": }
        sqlserver_tsql{ "v79083_attach_job_to_schedule_for_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql_attach_sched,
          onlyif   => $sql_attach_sched_check,
          require  => Sqlserver::Config[$instance],
        }
      }
    }

  }
}
