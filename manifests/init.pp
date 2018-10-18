# init.pp
#
# This module secures Microsoft SQL Server 2016
#
# @Usage
# class { '::secure_sqlserver':
#   sa_acct => '<username>',
# }
#
class secure_sqlserver (
  Array  $approved_shared_accounts,
  Array  $approved_sql_login_users,
  String $audit_filepath,
  Hash   $audit_maintainer_username,
  Hash   $backup_plan,
  Hash   $backup_recovery_model_settings,
  Hash   $certificate_backup,
  String $db_master_key_encryption_password,
  Hash   $new_database_owner,
  Hash   $schema_owners,
  Hash   $temporal_tables,
  Hash   $transparent_data_encryption,
  String $port = 1433,
  ) {

  class { '::secure_sqlserver::controller':
    approved_shared_accounts          => $::secure_sqlserver::approved_shared_accounts,
    approved_sql_login_users          => $::secure_sqlserver::approved_sql_login_users,
    audit_filepath                    => $::secure_sqlserver::audit_filepath,
    audit_maintainer_username         => $::secure_sqlserver::audit_maintainer_username,
    backup_plan                       => $::secure_sqlserver::backup_plan,
    backup_recovery_model_settings    => $::secure_sqlserver::backup_recovery_model_settings,
    certificate_backup                => $::secure_sqlserver::certificate_backup,
    db_master_key_encryption_password => $::secure_sqlserver::db_master_key_encryption_password,
    new_database_owner                => $::secure_sqlserver::new_database_owner,
    schema_owners                     => $::secure_sqlserver::schema_owners,
    temporal_tables                   => $::secure_sqlserver::temporal_tables,
    transparent_data_encryption       => $::secure_sqlserver::transparent_data_encryption,
    port                              => $::secure_sqlserver::port,
  }

}
