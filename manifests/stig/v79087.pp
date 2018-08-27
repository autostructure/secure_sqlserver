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
define secure_sqlserver::stig::v79087 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    unless empty($facts['sqlserver_encryption_is_master_key_encrypted_by_server'][${database}]) {

      # Add audit rule to detect access of the database master key (DMK):

      $sql_audit_spec = "CREATE DATABASE AUDIT SPECIFICATION [STIG_AUDIT_SPEC_V79087_KEYACCESS]
      FOR SERVER AUDIT [STIG_AUDIT]
      ADD (UPDATE ON OBJECT::[sys].[key_encryptions] by [dbo]) ,
      ADD (SELECT ON OBJECT::[sys].[key_encryptions] by [dbo]) ,
      ADD (DELETE ON OBJECT::[sys].[key_encryptions] by [dbo])
      WITH (STATE = ON)"

      ::secure_sqlserver::log { "V-79087: ${instance}\\${database}: sql = \n${sql_audit_spec}": }

      sqlserver_tsql{ "v79087_database_audit_spec_${instance}_${database}":
        instance => $instance,
        command  => $sql_audit_spec,
        require  => Sqlserver::Config[$instance],
      }

    }

  }
}
