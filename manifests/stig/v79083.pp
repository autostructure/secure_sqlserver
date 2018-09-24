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
