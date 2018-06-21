# This class manages DISA STIG vulnerability: V-79129
# SQL Server must protect against a user falsely repudiating by ensuring the
# NT AUTHORITY/SYSTEM account is not used for administration.
#
# Type TypeDescription
# ---- ------------------------
# C    CERTIFICATE_MAPPED_LOGIN
# R    SERVER_ROLE
# S    SQL_LOGIN
# U    WINDOWS_LOGIN
#
class secure_sqlserver::stig::v79129 (
  Boolean $enforced = false,
  String $instance = 'MSSQLSERVER',
) {
  # make sure the "NT AUTHORITY\SYSTEM" user only has the public role assigned.

  $assigned_roles = $facts['sqlserver_roles_assigned_to_nt_authority_system']
  $system_user = 'NT AUTHORITY\SYSTEM'

  $sql_server_roles = "SELECT srm.role_principal_id, sp1.name, srm.member_principal_id, sp2.name
                        FROM sys.server_role_members srm
             FULL OUTER JOIN sys.server_principals sp1
                          ON srm.role_principal_id = sp1.principal_id
             LEFT OUTER JOIN sys.server_principals sp2
                          ON srm.member_principal_id = sp2.principal_id
                       WHERE sp1.type = 'R'
                         AND sp2.name = '${system_user}'"

  $sql_db_roles =    "SELECT drm.role_principal_id, dp1.name, drm.member_principal_id, dp2.name
                        FROM sys.database_role_members drm
             FULL OUTER JOIN sys.database_principals dp1
                          ON drm.role_principal_id = dp1.principal_id
             LEFT OUTER JOIN sys.database_principals dp2
                          ON drm.member_principal_id = dp2.principal_id
                       WHERE dp1.type = 'R'
                         AND dp2.name = '${system_user}'"

  $keys = keys($hash)
  $assigned_roles.each |$single_role| {
    $sql_ddl = "ALTER SERVER ROLE ${single_role} DROP MEMBER ${system_user};"
    sqlserver_tsql{ 'Export master service key to temp file for backup':
      instance => $instance,
      command  => $sql_ddl,
      # onlyif   => '',
      # notify   => Exec[copy to backup medium],
    }
  }


  #sqlserver_tsql{ 'create-logon-trigger-to-limit-concurrent-sessions':
  #  instance => $db,
  #  command  => $sql_trigger,
  #  onlyif   => $sql_check,
  #}

}
