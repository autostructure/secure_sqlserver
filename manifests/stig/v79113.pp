# v79113.pp
#
# This class manages DISA STIG vulnerability: V-79113
# SQL Server must use NSA-approved cryptography to protect classified information
# in accordance with the data owners requirements.
#
# QUESTION: Am I creating a new master key here, or did 79085 take care of encrypting it???
# $sql_master = "USE master;
# CREATE MASTER KEY ENCRYPTION BY PASSWORD='${tde_password}';
#
# Enable Transparent Data Encryption (TDE):
# There are two encryptions involved with TDE:
# 1) a TDE certificate or TDE asymmetric key, and
# 2) a symmetric database encryption key (DEK).
#
define secure_sqlserver::stig::v79113 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    $tde_hash = lookup('secure_sqlserver::transparent_data_encryption')

    $tde_enabled = $database in $tde_hash

    if $tde_enabled {

      $tde_cert_name = $tde_hash[$database]['certname']
      $tde_password = $tde_hash[$database]['password']

      $sql_master = "USE master;
      CREATE CERTIFICATE ${tde_cert_name}
      ENCRYPTION BY PASSWORD = '${tde_password}'
      WITH
      SUBJECT='TDE_DB_Encryption_${database}';"
      # , EXPIRY_DATE = 'expiration date: yyyymmdd';S

      ::secure_sqlserver::log { "V-79113: ${instance}\\${database}: sql = \n${sql_master}": }

      sqlserver_tsql{ "v79113_enable_tde_${instance}_${database}":
        instance => $instance,
        command  => $sql_master,
        require  => Sqlserver::Config[$instance],
      }

      $sql = "USE ${database};

      CREATE DATABASE ENCRYPTION KEY
      WITH ALGORITHM = AES_256
      ENCRYPTION BY SERVER CERTIFICATE ${tde_cert_name};

      ALTER DATABASE ${database} SET ENCRYPTION ON;"

      ::secure_sqlserver::log { "V-79113: ${instance}\\${database}: sql = \n${sql}": }

      sqlserver_tsql{ "v79113_enable_tde_on_${instance}_${database}":
        instance => $instance,
        command  => $sql,
        require  => Sqlserver::Config[$instance],
      }

      # Once the encryption is turned on, depending on the size of the database, it may take some time to complete.
      # You can monitor the status by querying the sys.dm_database_encryption_keys DMV.

      # Backup Certificate (not a requirement of this vulnerability)
      #
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
    }

  }

}
