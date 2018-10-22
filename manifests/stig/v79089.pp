# v79089.pp
#
# The Certificate used for encryption must be backed up, stored offline and off-site.
#
# ADD TO control-repo hiera.yaml...
# - name: "Data includes passwords (encrypted)"
#   lookup_key: eyaml_lookup_key
#   path: "node/%{trusted.certname}.eyaml"
#   options:
#     pkcs7_private_key: /etc/puppetlabs/puppet/keys/private_key.pkcs7.pem
#     pkcs7_public_key:  /etc/puppetlabs/puppet/keys/public_key.pkcs7.pem
#
# Backup Process:
# Write file locally (encrypted)
# Use File resource to limit access to share dir. (request dedicated share)
# Afterwards, the vm team does backup to NAS (which get off-site tape backups)
#
define secure_sqlserver::stig::v79089 (
  Hash          $certificate_backup,
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    # 3dH85Hhk003GHk2597gheij4
    $database_certificates  = $facts['sqlserver_certificates']

    unless $database_certificates[$database] == undef {
      $certificates = database_certificates[$database]
    }

/*
    unless $certificate_backup[$database] == undef {
      $certificate_name               = $certificate_backup[$database]['certificate_name']
      $certificate_password           = $certificate_backup[$database]['certificate_password']
      $certificate_backup_private_key = $certificate_backup[$database]['certificate_backup_private_key']
      $certificate_backup_directory   = $certificate_backup[$database]['certificate_backup_directory']
      $certificate_backup_filename    = $certificate_backup[$database]['certificate_backup_filename']
      $delim = $certificate_backup_directory[-1,1] ? {
        '\\'    => '',
        default => '\\',
      }
      $certificate_backup_filepath    = "${certificate_backup_directory}${delim}${certificate_backup_filename}"
    }
*/

    # path is the namevar so a duplicate resource error arises (title isn't namevar)
    # file { "Create directory for encryption certificate backup file for ${database}.":
    #   ensure => directory,
    #   path   => $certificate_backup_directory,
    #   before => Sqlserver_tsql["Backup database encryption certificate for ${database}"],
    # }

    # $sql_backup_certificate = "USE ${database}; BACKUP CERTIFICATE '${certificate_name}' TO FILE = '${certificate_backup_filepath}'
    # WITH PRIVATE KEY (FILE = '${certificate_backup_private_key}', ENCRYPTION BY PASSWORD = '${certificate_password}')"

    unless empty($certificates) {
      $certificates.each |$certificate| {
        $certificate_backup_filepath = "C:\\Windows\\Temp\\${certificate}.bak"
        $certificate_password = 'test'
        $sql_backup_certificate = "USE ${database}; BACKUP CERTIFICATE '${certificate}' TO FILE = '${certificate_backup_filepath}' ENCRYPTION BY PASSWORD = '${certificate_password}'" #lint:ignore:140chars

        sqlserver_tsql{ "Backup database encryption certificate for ${database}":
          instance => $instance,
          database => $database,
          command  => $sql_backup_certificate,
          require  => Sqlserver::Config[$instance],
          # onlyif   => '',
          # notify   => Exec[copy to backup medium],
        }

        # Do we have to open the master key w/a password first?
        # SQL if you need to decrypt the key first.
        # $key_export_sql = "USE ${db_instance};
        #  OPEN MASTER KEY DECRYPTION BY PASSWORD = 'sfj5300osdVdgwdfkli7';
        #  BACKUP MASTER KEY TO FILE = 'c:\temp\exportedmasterkey'
        #      ENCRYPTION BY PASSWORD = 'sd092735kjn$&adsg';
        #  GO"

        # Copy the file to the backup medium and verify the copy.
        # Store the backup in a secure, off-site location.
        # (kicked off by notify above?)

        # Remove temp key backup file and directory.

        # file { "Remove local backup file for ${database}":
        #   ensure => absent,
        #   path   => $certificate_backup_filepath,
        #   # wrong...
        #   #require => Sqlserver_tsql['Export master service key to temp file for backup'],
        #   # instead use...
        #   #require => After copied to backup service.
        # }
        #
        # file { "Remove local backup directory for ${database}":
        #   ensure  =>  absent,
        #   path    => $certificate_backup_directory,
        #   require => File["Remove local backup file for ${database}"],
        # }
      }
    } else {
      ::secure_sqlserver::log { "secure_sqlserver::v79089:${instance}\\${database}: found no database certificates to backup.":
        loglevel => info,
      }
    }
  }
}
