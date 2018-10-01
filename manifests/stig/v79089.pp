# v79089.pp
#
# The Certificate used for encryption must be backed up, stored offline and off-site.
#
define secure_sqlserver::stig::v79089 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    notify { "v79089: ${instance}\\${database}: v79089 called.":
      loglevel => notice,
    }

    # 3dH85Hhk003GHk2597gheij4
    $database_certificates           = $facts['sqlserver_remote_database_accounts']
    $certificate_name                = lookup('secure_sqlserver::certificate_name')
    $certificate_encryption_password = lookup('secure_sqlserver::certificate_password')
    $certificate_backup_directory    = lookup('secure_sqlserver::certificate_backup_directory')
    $certificate_backup_filename     = lookup('secure_sqlserver::certificate_backup_directory')
    $certificate_backup_path         = "${certificate_backup_directory}\\${certificate_backup_filename}"

    file { 'Create directory for temporary key backup file.':
      ensure => directory,
      path   => $key_temp_backup_dir,
      before => Sqlserver_tsql['Export master service key to temp file for backup'],
    }

    # refactor and iterate through all instances...
    $db_instance = 'MSSQLSERVER'

    # Do we have to open the master key w/a password first?
    # SQL if you need to decrypt the key first.
    # $key_export_sql = "USE ${db_instance};
    #  OPEN MASTER KEY DECRYPTION BY PASSWORD = 'sfj5300osdVdgwdfkli7';
    #  BACKUP MASTER KEY TO FILE = 'c:\temp\exportedmasterkey'
    #      ENCRYPTION BY PASSWORD = 'sd092735kjn$&adsg';
    #  GO"

    $key_export_sql = "BACKUP SERVICE MASTER KEY TO FILE = '${key_temp_backup_file}'
      ENCRYPTION BY PASSWORD = '${key_encryption_password}'"

    # $key_export_sql = "USE ${db_instance};
    #   GO
    #   BACKUP SERVICE MASTER KEY TO FILE = '${key_temp_backup_filepath}'
    #   ENCRYPTION BY PASSWORD = '${key_encryption_password}';
    #   GO"

    sqlserver_tsql{ 'Export master service key to temp file for backup':
      instance => $db_instance,
      command  => $key_export_sql,
      # onlyif   => '',
      # notify   => Exec[copy to backup medium],
    }

    # Copy the file to the backup medium and verify the copy.
    # Store the backup in a secure, off-site location.
    # (kicked off by notify above?)

    # Remove temp key backup file.

    file { 'Remove temporary key backup file.':
      ensure =>  absent,
      path   => $key_temp_backup_file,
      # wrong...
      #require => Sqlserver_tsql['Export master service key to temp file for backup'],
      # instead use...
      #require => After copied to backup service.
    }

    file { 'Remove directory for temporary key backup file.':
      ensure  =>  absent,
      path    => $key_temp_backup_dir,
      require => File['Remove temporary key backup file.'],
    }



  }
}
