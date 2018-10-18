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
  port,
  sa_acct,
  approved_sql_login_users,
  approved_shared_accounts,
  audit_maintainer_username,
  audit_filepath,
  backup_recovery_model_settings,
  backup_plan,
  certificate_backup,
  db_master_key_encryption_password,
  db_master_key_encrypt_backup_file_password,
  db_master_key_encrypt_backup_file_filepath,
  new_database_owner,
  schema_owners,
  temporal_tables,
  transparent_data_encryption,
  ) {

  class { '::secure_sqlserver::controller': }

}
