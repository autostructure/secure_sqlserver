# v79207.pp
# The Service Master Key must be backed up, stored offline and off-site.
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

# Enable TDE based on a yaml file property.
# There are two encryptions involved with TDE:
# 1) a TDE certificate or TDE asymmetric key, and
# 2) a symmetric database encryption key (DEK).


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
#
class secure_sqlserver::stig::v79207 (
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
