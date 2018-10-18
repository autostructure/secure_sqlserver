# v79077.pp
#
# This class manages DISA STIG vulnerability: V-79071
# SQL Server must protect against a user falsely repudiating by ensuring databases
# are not in a trust relationship.
#
# NOTE:
# If the database is MSDB, trustworthy is required to be enabled and therefore, this is not a finding.
#

###################################################################################
# STIG Info...
###################################################################################
# Check Text: Obtain a listing of schema ownership from the server documentation.
#
# Execute the following query to obtain a current listing of schema ownership.
#
# SELECT S.name AS schema_name, P.name AS owning_principal
# FROM sys.schemas S
# JOIN sys.database_principals P ON S.principal_id = P.principal_id
# ORDER BY schema_name
#
# If any schema is owned by an unauthorized database principal, this is a finding.
#
# Fix Text: Transfer ownership of database schemas to authorized database principals.
#
# ALTER AUTHORIZATION ON SCHEMA::[<Schema Name>] TO [<Principal Name>]

define secure_sqlserver::stig::v79077 (
  Hash          $schema_owners,
  Boolean       $enforced = false,
  String        $database,
  String[1,16]  $instance = 'MSSQLSERVER',
) {
  if $enforced {

    $skip_schemas = $schema_owners
    $schemas = $facts['sqlserver_database_schema_owners']

    $schemas.each |$schema_hash| {

      $schema = schema_hash['schema_name']
      $principal = schema_hash['owning_principal']

      $schema_owner = $skip_schemas[$database][$schema]

      # skip the four pre-installed databases
      # skip if the db owner already matches the yaml file setting
      #unless $schema_owner == $principal or downcase($database) == 'msdb' or empty($schema) or empty($principal)  {
      unless $schema_owner == $principal or empty($schema) or empty($principal) or downcase($database) in ['master','msdb','model','tempdb'] {
      $sql = "ALTER AUTHORIZATION ON SCHEMA::${schema} TO ${principal}"

        ::secure_sqlserver::log { "v79077: calling tsql module for, ${instance}\\${database}\\${schema}\\${principal}, using sql = \n${sql}": }

        sqlserver_tsql{ "v79077_alter_auth_on_schema_${instance}_${database}_${schema}_${principal}":
          instance => $instance,
          database => $database,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      }
    }

  }
}
