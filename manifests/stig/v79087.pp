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
# Since the key is already encrypted in v79085,
# the only remaining task is adding an audit rule to
# capture database key access by the DBAs.
#
#
# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j
# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=24270
#
# class_type	Class Description
# AK	ASYMMETRIC KEY
# AS	ASSEMBLY
# CR	CERTIFICATE
# CT	CONTRACT
# DC	DATABASE SCOPED CREDENTIAL
# EL	EXTERNAL LIBRARY
# MT	MESSAGE TYPE
# SK	SYMMETRIC KEY
# MK  MASTER KEY
#
# SQL Server	24070	Issued a change server master key command (action_id AL class_type MK)
# SQL Server	24071	Issued a back up server master key command (action_id BA class_type MK)
# SQL Server	24072	Issued a restore server master key command (action_id RS class_type MK)
# SQL Server	24097	Issued a create database master key command (action_id CR class_type MK)
# SQL Server	24098	Issued a change database master key command (action_id AL class_type MK)
# SQL Server	24099	Issued a delete database master key command (action_id DR class_type MK)
# SQL Server	24100	Issued a back up database master key command (action_id BA class_type MK)
# SQL Server	24101	Issued a restore database master key command (action_id RS class_type MK)
# SQL Server	24102	Issued an open database master key command (action_id OP class_type MK)
#
# SQL Server	24103	Issued a create database symmetric key command (action_id CR class_type SK)
# SQL Server	24104	Issued a change database symmetric key command (action_id AL class_type SK)
# SQL Server	24105	Issued a delete database symmetric key command (action_id DR class_type SK)
# SQL Server	24106	Issued a back up database symmetric key command (action_id BA class_type SK)
# SQL Server	24107	Issued an open database symmetric key command (action_id OP class_type SK)
# SQL Server	24152	Issued a change symmetric key owner command (action_id TO class_type SK)
# SQL Server	24228	Issued grant symmetric key permissions command (action_id G class_type SK)
# SQL Server	24229	Issued grant symmetric key permissions with grant command (action_id GWG class_type SK)
# SQL Server	24230	Issued deny symmetric key permissions command (action_id D class_type SK)
# SQL Server	24231	Issued deny symmetric key permissions with cascade command (action_id DWC class_type SK)
# SQL Server	24232	Issued revoke symmetric key permissions command (action_id R class_type SK)
# SQL Server	24233	Issued revoke symmetric key permissions with grant command (action_id RWG class_type SK)
# SQL Server	24234	Issued revoke symmetric key permissions with cascade command (action_id RWC class_type SK)
#
# SQL Server	24093	Issued a create asymmetric key command (action_id CR class_type AK)
# SQL Server	24094	Issued a change asymmetric key command (action_id AL class_type AK)
# SQL Server	24095	Issued a delete asymmetric key command (action_id DR class_type AK)
# SQL Server	24096	Issued an access asymmetric key command (action_id AS class_type AK)
# SQL Server	24154	Issued a change asymmetric key owner command (action_id TO class_type AK)
# SQL Server	24242	Issued grant asymmetric key permissions command (action_id G class_type AK)
# SQL Server	24243	Issued grant asymmetric key permissions with grant command (action_id GWG class_type AK)
# SQL Server	24244	Issued deny asymmetric key permissions command (action_id D class_type AK)
# SQL Server	24245	Issued deny asymmetric key permissions with cascade command (action_id DWC class_type AK)
# SQL Server	24246	Issued revoke asymmetric key permissions command (action_id R class_type AK)
# SQL Server	24247	Issued revoke asymmetric key permissions with grant command (action_id RWG class_type AK)
# SQL Server	24248	Issued revoke asymmetric key permissions with cascade command (action_id RWC class_type AK)
#
# Note:
# While the action_id and class_type fields are of type varchar in sys.fn_get_audit_file, they can only be used with numbers when they are a predicate source for filtering. To get the list of values to be used with class_type, execute the following query:
#
# SELECT spt.[name], spt.[number]
# FROM   [master].[dbo].[spt_values] spt
# WHERE  spt.[type] = N'EOD'
# ORDER BY spt.[name];
#
# Source: https://docs.microsoft.com/en-us/sql/t-sql/statements/create-server-audit-transact-sql?view=sql-server-2017
#
#
# 19268 DATABASE ENCRYPTION KEY
# 19277 MASTER KEY
# 19283 SYMMETRIC KEY
# 19265 ASSYMMETRIC KEY
# 19521 ASSYMETRIC KEY LOGIN
# 21825 ASSYMMETRIC KEY USER
# 19267 COLUMN ENCRYPTION KEY
# 19779 COLUMN MASTER KEY
#
define secure_sqlserver::stig::v79087 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    # Add audit rule to detect access of the database master key (DMK):
    unless empty($facts['sqlserver_encryption_is_master_key_encrypted_by_server'][${database}]) {

      $audit_filepath = lookup('secure_sqlserver::audit_filepath')

      $sql_create_audit = "CREATE SERVER AUDIT [STIG_AUDIT_ENCRYPTION_KEYS]
TO FILE ( FILEPATH ='${audit_filepath}' )
   WITH ( QUEUE_DELAY = 1000
        , ON_FAILURE = FAIL_OPERATION )
  WHERE class_type = 19277
     OR class_type = 19283
     OR class_type = 19265
     OR class_type = 19268"

      $sql_create_spec = "CREATE DATABASE AUDIT SPECIFICATION [STIG_AUDIT_SPEC_V79087_KEYACCESS]
   FOR SERVER AUDIT [STIG_AUDIT_ENCRYPTION_KEYS]
   ADD (DATABASE_OBJECT_ACCESS_GROUP)
  WITH (STATE = ON)"

      $sql_enable_audit = "ALTER SERVER AUDIT [STIG_AUDIT_ENCRYPTION_KEYS] WITH (STATE = ON);"

      ::secure_sqlserver::log { "V-79087: ${instance}\\${database}: sql (create_audit) = \n${sql_create_audit}": }

      sqlserver_tsql{ "v79087_create_audit_for_keys_${instance}_${database}":
        instance => $instance,
        command  => $sql_create_audit,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "V-79087: ${instance}\\${database}: sql (create_audit_spec) = \n${sql_create_spec}": }

      sqlserver_tsql{ "v79087_create_db_audit_spec_for_keys_${instance}_${database}":
        instance => $instance,
        command  => $sql_create_spec,
        require  => Sqlserver::Config[$instance],
      }

      ::secure_sqlserver::log { "V-79087: ${instance}\\${database}: sql (enable_audit) = \n${sql_enable_audit}": }

      sqlserver_tsql{ "v79087_enable_audit_for_keys_${instance}_${database}":
        instance => $instance,
        command  => $sql_enable_audit,
        require  => Sqlserver::Config[$instance],
      }

    }

  }

}
