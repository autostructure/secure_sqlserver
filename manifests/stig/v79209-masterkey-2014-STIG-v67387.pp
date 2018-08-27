# v79209.pp
# The Master Key must be backed up, stored offline and off-site.
#
# *** Important Security Information ***
# Accessing objects secured by the service master key requires either
# the SQL Server Service account that was used to create the key or the computer (machine) account.
# That is, the computer is tied to the system where the key was created.
# You can change the SQL Server Service account or the computer account without losing access to the key.
# However, if you change both, you will lose access to the service master key.
# If you lose access to the service master key without one of these two elements,
# you be unable to decrypt data and objects encrypted by using the original key.
# Connections secured with the service master key cannot be restored without the service master key.
# Access to objects and data secured with the database master key require only the password that is used to help secure the key.
#
# Source: https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/sql-server-and-database-encryption-keys-database-engine?view=sql-server-2017
#
################################################################################
################################################################################
#
# v79087.pp
#
# This class manages DISA STIG vulnerability: V-79087
# The Database Master Key must be encrypted by the Service Master Key,
# where a Database Master Key is required
# and another encryption method has not been specified.
#
# So the concern is that a DBA with instance-level access
# can use the Service Master Key (SMK) to unencrypt the
# Database Master Key (DMK), specific to an application.
# Using an ALTER command, specified in v79085, we can
# protect the key with a password as well:
#
#   ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = '<pwd>'
#
# This should prevent the DBAs from accessing the DMK.
# (unless they are given the password).
#
define secure_sqlserver::stig::v79087 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    # SELECT name
    # FROM [master].sys.databases
    # WHERE is_master_key_encrypted_by_server = 1
    # AND owner_sid <> 1
    # AND state = 0
    # AND name = $database
    # (Note that this query assumes that the [sa] account is not used as the owner of application databases, in keeping with other STIG guidance. If this is not the case, modify the query accordingly.)

    if $facts['sqlserver_encryption_is_master_key_encrypted_by_server'] {

      # password regex test for at least:
      # a lowercase letter,
      # an uppercase letter,
      # a digit,
      # a special character (i.e. a non-word character) and
      # a length of 15+ characters...
      $regex_password_check = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{15,}$/'
      $password = lookup('secure_sqlserver::database_master_key_backup_file_encryption_password')
      $filepath = lookup('secure_sqlserver::database_master_key_backup_file_encryption_filepath')

      #$facts['sqlserver_sql_authenticated_users'].each |String $sql_login| {

      if $password =~ $regex_password_check {
        $sql = "USE ${database}; BACKUP MASTER KEY TO FILE = '${filepath}' ENCRYPTION BY PASSWORD = '${password}';"
        ::secure_sqlserver::log { "${instance}\\${database}: v79087 sql = \n${sql}": }
        sqlserver_tsql{ "v79087_database_master_key_backup_${instance}_${database}_${username}":
          instance => $instance,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      } else {
        ::secure_sqlserver::log { "V-79087: ${instance}\\${database} needs a valid password (pwd failed check).":
          loglevel => debug,
        }
      }

    } else {
      ::secure_sqlserver::log { "V-79087: ${instance}\\${database} is not encrypted.":
        loglevel => debug,
      }
    }

  }
}

################################################################################
################################################################################

class secure_sqlserver::stig::v79209 (
  Boolean $enforced = false,
) {

  # NOTE!!!!!
  # 2014_STIG_v67387 code below (adapt this 2014 code for 2016)...


  #TODO: SME Questions...
  # 1. Is this handled procedurally?  Can it be automated?
  # 2. Is the service master key encrypted?
  # 3. If so, we need to configure a hiera password?
  # 4. How does the key get backed up?
  # 5. Backed up to what location?

  #TODO: replace sample values...
  $key_encryption_password = '3dH85Hhk003GHk2597gheij4'
  $key_temp_backup_dir = 'c:\secure_sqlserver_temp'
  $key_temp_backup_file = "${key_temp_backup_dir}\service_master_key"

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





################################################################################
################################################################################




# v79113.pp
#
# This class manages DISA STIG vulnerability: V-79113
# SQL Server must use NSA-approved cryptography to protect classified information
# in accordance with the data owners requirements.
#
define secure_sqlserver::stig::v79113 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    lookup('secure_sqlserver::stig::v79061::enforced')

    # Enable TDE based on a yaml file property.
    # There are two encryptions involved with TDE:
    # 1) a TDE certificate or TDE asymmetric key, and
    # 2) a symmetric database encryption key (DEK).

    USE master;
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = '';
    CREATE CERTIFICATE . . .;
    USE ;
    CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE ;
    ALTER DATABASE
    SET ENCRYPTION ON;

    # EKM
    #
    # By default, Extensible Key Management is off. To enable this feature,
    # use the sp_configure command that has the following option and value, as in the following example:
    #
    # Copy
    # sp_configure 'show advanced', 1
    # GO
    # RECONFIGURE
    # GO
    # sp_configure 'EKM provider enabled', 1
    # GO
    # RECONFIGURE
    # GO

    # The following example creates a database symmetric key and encrypts it using a key on an EKM module.
    #
    # CREATE SYMMETRIC KEY Key1
    # WITH ALGORITHM = AES_256
    # ENCRYPTION BY EKM_AKey1;
    # GO
    # --Open database key
    # OPEN SYMMETRIC KEY Key1
    # DECRYPTION BY EKM_AKey1
    #
    # Note: You cannot encrypt one EKM key with another EKM key.
    # Source: https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/extensible-key-management-ekm?view=sql-server-2017

    # Use DoD code-signing certificates to create asymmetric keys stored in the database and used to encrypt sensitive data stored in the database.
    #
    # Run the following SQL script to create a certificate:
    # USE
    # CREATE CERTIFICATE
    # ENCRYPTION BY PASSWORD = <'password'>
    # FROM FILE = <'path/file_name'>
    # WITH SUBJECT = 'name of person creating key',
    # EXPIRY_DATE = '<'expiration date: yyyymmdd'>'
    #
    # Run the following SQL script to create a symmetric key and assign an existing certificate:
    # USE
    # CREATE SYMMETRIC KEY <'key name'>
    # WITH ALGORITHM = AES_256
    # ENCRYPTION BY CERTIFICATE
    #
    # For Transparent Data Encryption (TDE):
    # USE master;
    # CREATE MASTER KEY ENCRYPTION BY PASSWORD = '';
    # CREATE CERTIFICATE . . .;
    # USE ;
    # CREATE DATABASE ENCRYPTION KEY
    # WITH ALGORITHM = AES_256
    # ENCRYPTION BY SERVER CERTIFICATE ;
    # ALTER DATABASE
    # SET ENCRYPTION ON;

    # Create Master Key
    # We must first create the master key.
    # It must be created in the master database,
    # so as a precautionary measure I like to begin this statement with the USE MASTER command.
    #
    # USE Master;
    # GO
    # CREATE MASTER KEY ENCRYPTION
    # BY PASSWORD='InsertStrongPasswordHere';
    # GO
    #
    #
    # Create Certificate protected by master key
    # Once the master key is created along with the strong password (that you should remember or save in a secure location), we will go ahead and create the actual certificate.
    #
    # CREATE CERTIFICATE TDE_Cert
    # WITH
    # SUBJECT='Database_Encryption';
    # GO
    #
    # The certificate’s name is “TDE_Cert” and I gave it a generic subject. Some Database Administrators like to put the name of the actual database that they are going to encrypt in there. It is totally up to you.
    #
    #
    # Create Database Encryption Key
    # Now, we must utilize our USE command to switch to the database that we wish to encrypt. Then we create a connection or association between the certificate that we just created and the actual database. Then we indicate the type of encryption algorithm we are going to use. In this case it will be AES_256 encryption.
    #
    # USE <DB>
    # GO
    # CREATE DATABASE ENCRYPTION KEY
    # WITH ALGORITHM = AES_256
    # ENCRYPTION BY SERVER CERTIFICATE TDE_Cert;
    # GO
    #
    #
    # Enable Encryption
    # Finally, we can enable encryption on our database by using the ALTER DATABASE command.
    #
    # ALTER DATABASE <DB>
    # SET ENCRYPTION ON;
    # GO
    #
    # Once the encryption is turned on, depending on the size of the database, it may take some time to complete. You can monitor the status by querying the sys.dm_database_encryption_keys DMV.
    #
    # Backup Certificate
    # It’s important to backup the certificate you created and store it in a secure location.
    # If the server ever goes down and you need to restore it elsewhere,
    # you will have to import the certificate to the server.
    # In certain environments, the DR servers are already stood up and on warm/hot standby,
    # so it’s a good idea to just preemptively import the saved certificate to these servers.
    #
    # BACKUP CERTIFICATE TDE_Cert
    # TO FILE = 'C:\temp\TDE_Cert'
    # WITH PRIVATE KEY (file='C:\temp\TDE_CertKey.pvk',
    # ENCRYPTION BY PASSWORD='InsertStrongPasswordHere')
    #
    # Remember to store the certificate in a safe and available locations (not a temporary one like this example).

    # Enable Transparent Data Encryption (TDE):
    USE master;

    CREATE MASTER KEY ENCRYPTION BY PASSWORD = '';

    CREATE CERTIFICATE . . .;

    # loop through databases...
    USE ;

CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE ;

ALTER DATABASE SET ENCRYPTION ON;

  }

}
