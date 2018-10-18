# This class manages other sqlserver classes.
#
# Usage:
# class { '::secure_sqlserver':
#   sa_acct => '<username>',
# }
#
class secure_sqlserver::controller (
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
  String $port,
  String $sa_acct,
  ) {
  # NOTE: using 'Down-Level Logon Name' format for usernames.
  $netbios_user = $facts['identity']['user']
  $fqdn_user = $facts['id']

  $instances = $facts['sqlserver_instances']['SQL_2016'].keys

  if empty($instances) {
    fail('secure_sqlserver failure: No instances of SQL Server 2016 were discovered in the sqlserver_instances puppet fact (part of the puppetlabs-sqlserver module).')
  }

  $single_instance = $instances[0]

  notify { 'secure_sqlserver:_controller_msg1':
    message  => "secure_sqlserver::controller: Running in SINGLE_INSTANCE mode: instance=${single_instance}",
    loglevel => info,
  }

  # need sqlserver_config for sqlserver_tsql commands, set auth to windows authentication (no passwords required)
  sqlserver::config { $single_instance:
    admin_login_type => 'WINDOWS_LOGIN',
  }

  class { '::secure_sqlserver::secure_instance':
    sa_acct  => $sa_acct,
    instance => $single_instance,
    port     => $port,
  }

  # Next, cycle through all the databases and secure them...

  $databases = $facts['sqlserver_databases']

  if empty($databases) {
    # fail('secure_sqlserver failure: No SQL Server 2016 databases were discovered.')
    ::secure_sqlserver::log { 'No SQL Server 2016 databases were discovered.':
      loglevel => alert,
    }
  }

  $databases.each |String $database| {

    ::secure_sqlserver::log { "Securing the '${database}' database.":
      loglevel => info,
    }

    # using a define type over class, since we make multiple calls...
    ::secure_sqlserver::secure_database { "secure_database_${database}":
      instance                                   => $single_instance,
      database                                   => $database,
      approved_shared_accounts                   => $approved_shared_accounts,
      approved_sql_login_users                   => $approved_sql_login_users,
      audit_filepath                             => $audit_filepath,
      audit_maintainer_username                  => $audit_maintainer_username,
      backup_plan                                => $backup_plan,
      backup_recovery_model_settings             => $backup_recovery_model_settings,
      certificate_backup                         => $certificate_backup,
      db_master_key_encryption_password          => $db_master_key_encryption_password,
      new_database_owner                         => $new_database_owner,
      schema_owners                              => $schema_owners,
      temporal_tables                            => $temporal_tables,
      transparent_data_encryption                => $transparent_data_encryption,
    }

  }

}
