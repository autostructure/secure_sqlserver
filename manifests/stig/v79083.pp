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
define secure_sqlserver::stig::v79083 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    $backup_recovery_model_settings = lookup('secure_sqlserver::backup_recovery_model_settings')
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
            notify { "v79083: ${instance}\\${database}: recovery_model = ${model}, target = ${target_recovery_model}":
              loglevel => notice,
            }
            if $model != $target_recovery_model and !empty($target_recovery_model) {
              $sql = "ALTER DATABASE ${database} SET RECOVERY ${target_recovery_model}"
              ::secure_sqlserver::log { "v79083: ${instance}\\${database}: recovery_model = ${model}, changing to ${target_recovery_model}":
                loglevel => notice,
              }
              ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql}": }
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
            $sql = "ALTER DATABASE ${database} SET RECOVERY ${target_recovery_model}"
            ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql}": }
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
    # create schedule
    # attach job to schedule

    # Object names...
    $db = upcase($database)
    $job_name = "STIG_JOB_V79083_BACKUP_${db}"
    $schedule_name = "STIG_JOB_V79083_SCHED_${db}"

    # Hiera lookups...
    $backup_plans = lookup('secure_sqlserver::backup_plan')

    unless empty($backup_plans[$database]) {
      $backup_plan_desc = $backup_plans[$database]['description']
      $backup_plan_disk = $backup_plans[$database]['disk']
      $backup_plan_diff = $backup_plans[$database]['diff']
      $backup_plan_logs = $backup_plans[$database]['log']

      # backup command...
      # T-SQL complained that the command should be 128 characters.

      # BACKUP DATABASE ${database} TO DISK = '${backup_plan_disk}' WITH CHECKSUM, DESCRIPTION = '${backup_plan_desc}';
      # BACKUP DATABASE ${database} TO DISK = '${backup_plan_disk}.dif' WITH DIFFERENTIAL, CHECKSUM, DESCRIPTION = '${backup_plan_desc}';
      # BACKUP LOG ${database} TO DISK = '${backup_plan_logs}' WITH CHECKSUM, DESCRIPTION = '${backup_plan_desc}';
      # 12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678

      $sql_full_backup = "BACKUP DATABASE ${database} TO DISK = ''${backup_plan_disk}'' WITH CHECKSUM"
      $sql_diff_backup = "BACKUP DATABASE ${database} TO DISK = ''${backup_plan_diff}'' WITH DIFFERENTIAL, CHECKSUM"
      $sql_logs_backup = "BACKUP LOG ${database} TO DISK = ''${backup_plan_logs}'' WITH CHECKSUM"
      # , DESCRIPTION = '${backup_plan_desc}'

      ::secure_sqlserver::log { "v79083: CHECK #1 -- calling tsql module for, ${instance}\\${database}, using sql = \n${sql_full_backup}":
        loglevel => notice,
      }

      $sql_add_job = "EXEC dbo.sp_add_job @job_name = N'${job_name}' ;"

      $sql_add_job_full = "EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'${job_name}',
        @step_name = 'Full database backup for ${database}.',
        @subsystem = 'TSQL',
        @command = '${sql_full_backup}',
        @retry_attempts = 5,
        @retry_interval = 5 ;"

      ::secure_sqlserver::log { "v79083: CHECK #2 -- calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_full}":
        loglevel => notice,
      }

      $sql_add_job_diff = "EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'${job_name}',
        @step_name = 'Differential database backup for ${database}.',
        @subsystem = 'TSQL',
        @command = '${$sql_diff_backup}',
        @retry_attempts = 5,
        @retry_interval = 5 ;"

      $sql_add_job_logs = "EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'${job_name}',
        @step_name = 'Backup database logs for ${database}.',
        @subsystem = 'TSQL',
        @command = '${sql_logs_backup}',
        @retry_attempts = 5,
        @retry_interval = 5 ;"

      $sql_add_sched = "EXEC msdb.dbo.sp_add_schedule
        @schedule_name = N'${schedule_name}' ,
        @freq_type = 4,
        @freq_interval = 1,
        @active_start_time = 010000 ;"

      $sql_attach_sched = "EXEC msdb.dbo.sp_attach_schedule
        @job_name = N'${job_name}',
        @schedule_name = N'${schedule_name}' ;"

      ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job}": }
      sqlserver_tsql{ "v79083_create_job_for_backup_of_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_add_job,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_full}": }
      sqlserver_tsql{ "v79083_create_job_for_full_backup_of_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_add_job_full,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_diff}": }
      sqlserver_tsql{ "v79083_create_job_for_diff_backup_of_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_add_job_diff,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_job_logs}": }
      sqlserver_tsql{ "v79083_create_job_for_log_backup_of_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_add_job_logs,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_add_sched}": }
      sqlserver_tsql{ "v79083_create_schedule_for_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_add_sched,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "v79083: calling tsql module for, ${instance}\\${database}, using sql = \n${sql_attach_sched}": }
      sqlserver_tsql{ "v79083_attach_job_to_schedule_for_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_attach_sched,
        require  => Sqlserver::Config[$instance],
      }
    }

  }
}
