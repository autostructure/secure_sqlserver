# This class manages DISA STIG vulnerability: V-79129
# SQL Server must protect against a user falsely repudiating by ensuring the
# NT AUTHORITY SYSTEM account is not used for administration.
#
class secure_sqlserver::stig::v79129 (
  Boolean $enforced = false,
) {

  include ::secure_sqlserver::logon

  # make sure this user only has the public role assigned.
  #$roles_hash = $facts['sqlserver_roles_assigned_to_nt_authority_system']
  $assigned_roles = $facts['sqlserver_roles_assigned_to_nt_authority_system']
  notify { 'roles-output':
    message => $assigned_roles,
  }
  #$assigned_roles = keys($roles_hash)
  #$assigned_roles.each |$key| {
  #  notify { $key:
  #    message => $key,
  #  }
  #}

  ::secure_sqlserver::log { $assigned_roles: }

  $system_user = 'NT AUTHORITY\SYSTEM'
  #$sql_ddl = "ALTER ROLE ${role_name} DROP MEMBER ${system_user}"

  $sql_check_server_roles = "SELECT srm.role_principal_id, sp1.name, srm.member_principal_id, sp2.name
FROM sys.server_role_members srm
FULL OUTER JOIN sys.server_principals sp1
ON srm.role_principal_id = sp1.principal_id
LEFT OUTER JOIN sys.server_principals sp2
ON srm.member_principal_id = sp2.principal_id
WHERE sp2.name = 'NT AUTHORITY\SYSTEM'
AND sp1.type = 'R'"

  $sql_check_db_roles = "SELECT drm.role_principal_id, dp1.name, drm.member_principal_id, dp2.name
FROM sys.database_role_members drm
FULL OUTER JOIN sys.database_principals dp1
ON drm.role_principal_id = dp1.principal_id
LEFT OUTER JOIN sys.database_principals dp2
ON drm.member_principal_id = dp2.principal_id
WHERE dp2.name = 'NT AUTHORITY\SYSTEM'
AND dp1.type = 'R'"

  $sql_ddl = "ALTER SERVER ROLE ${assigned_roles} DROP MEMBER ${system_user};"

  #sqlserver_tsql{ 'create-logon-trigger-to-limit-concurrent-sessions':
  #  instance => $db,
  #  command  => $sql_trigger,
  #  onlyif   => $sql_check,
  #}

}
