# v79081
#
# The role(s)/group(s) used to modify database structure (including but not necessarily limited to
# tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers,
# links to software external to SQL Server, etc.) must be restricted to authorized users.
#
###################################################################################
# STIG Info...
###################################################################################
# Check Text:
# Obtain a listing of users and roles who are authorized to modify database structure and logic modules
# from the server documentation. Execute the following query:
#
# SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
# CASE class
# WHEN 0 THEN DB_NAME()
# WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
# WHEN 3 THEN SCHEMA_NAME(major_id)
# ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
# END AS securable_name, DP.state_desc, DP.permission_name
# FROM sys.database_permissions DP
# JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
# LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
# WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
#
# SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
# FROM sys.database_principals R
# JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
# JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
# WHERE R.name IN ('db_ddladmin','db_owner')
# AND M.name != 'dbo'
#
# If any users or role permissions returned are not authorized to modify the specified object or type, this is a finding.
#
# Fix Text:
# Document and obtain approval for any non-administrative users who require the ability to
# modify database structure and logic modules.
#
# REVOKE ALTER ON [<Object Name>] TO [<Principal Name>]

define secure_sqlserver::stig::v79077 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    $roles_and_users = $facts['sqlserver_database_roles_and_users_with_modify']
    #
    # $schema_owners.each |$schema_hash| {
    #
    #   $schema = schema_hash['schema_name']
    #   $principal = schema_hash['owning_principal']
    # 
    #   ::secure_sqlserver::log { "v79081 altering schema: ${schema} for owner = ${principal} on ${instance}\\${database}":
    #     loglevel => debug,
    #   }
    #
    #   $schema_owner = $skip_schemas[$database][$schema]
    #
    #   # skip the four pre-installed databases
    #   # skip if the db owner already matches the yaml file setting
    #   unless $schema_owner == $principal or downcase($database) == 'msdb' or empty($schema) or empty($principal)  {
    #     $sql = "ALTER AUTHORIZATION ON SCHEMA::${schema} TO ${principal}"
    #
    #     ::secure_sqlserver::log { "v79077: calling tsql module for, ${instance}\\${database}\\${schema}\\${principal}, using sql = \n${sql}": }
    #
    #     sqlserver_tsql{ "v79077_alter_auth_on_schema_${instance}_${database}_${schema}_${principal}":
    #       instance => $instance,
    #       database => $database,
    #       command  => $sql,
    #       require  => Sqlserver::Config[$instance],
    #     }
    #   }
    # }

  }
}
