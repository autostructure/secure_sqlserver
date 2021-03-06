# v79073.pp
#
# This class manages DISA STIG vulnerability: V-79073
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM)
# to select which auditable events are to be audited.
#
# Fix Text:
# Create a database role specifically for audit maintainers, and give it permission to maintain audits,
# without granting it unnecessary permissions (The role name used here is an example; other names may be used.):
#


# QUESTION:
#
# How to I query the "database_principals" in a fact and get all databases info?
# - Add a database column and iterate through all databases and append output from sys.database_principals
# - Is there a view that combines all databases?

# How to I query the "database_principals" in a fact and get all databases info? 1) Add a database column and iterate through all databases and append output from sys.database_principals, or 2) Is there a view that combines all databases?

define secure_sqlserver::stig::v79073 (
  Hash          $audit_maintainer_username,
  String[1,16]  $instance,
  String        $database,
  Boolean       $enforced = false,
) {

  if $enforced {

    # Step 1: Create new audit role...

    # NOTE: omitting 'USE ${database};', the sqlserver_tsql's database parameter handles it.
    $sql_create = 'CREATE ROLE DATABASE_AUDIT_MAINTAINERS; GRANT ALTER ANY DATABASE AUDIT TO DATABASE_AUDIT_MAINTAINERS;'

    ::secure_sqlserver::log { "V-79073: create database_audit_maintainers audit role on ${instance}\\${database}: sql = \n${sql_create}": }
    sqlserver_tsql{ "v79073_create_database_audit_maintainers_${instance}_${database}":
      instance => $instance,
      database => $database,
      command  => $sql_create,
      require  => Sqlserver::Config[$instance],
      onlyif   => "IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DATABASE_AUDIT_MAINTAINERS' and type='R') THROW 50001, 'Missing DATABASE_AUDIT_MAINTAINERS role.', 10", #lint:ignore:140chars
    }

    # Step 2: Add audit maintainer user to new DATABASE_AUDIT_MAINTAINERS role...

    $audit_user = $audit_maintainer_username[$database]

    unless empty($audit_user) {

      $sql_new_user = "CREATE USER ${audit_user} WITHOUT LOGIN"

      ::secure_sqlserver::log { "V-79073: create audit maintainer user '${audit_user}' on ${instance}\\${database}: sql = \n${sql_new_user}": } #lint:ignore:140chars

      sqlserver_tsql{ "v79073_database_audit_maintainers_create_user_${instance}_${database}_${audit_user}":
        instance => $instance,
        database => $database,
        command  => $sql_new_user,
        require  => Sqlserver::Config[$instance],
        onlyif   => "IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name='${audit_user}') THROW 50002, 'Missing auditing user: ${audit_user}.',10", #lint:ignore:140chars
      }

      $sql_add = "ALTER ROLE DATABASE_AUDIT_MAINTAINERS ADD MEMBER ${audit_user};"

      ::secure_sqlserver::log { "V-79073: add member to role on ${instance}\\${database}: sql = \n${sql_add}": }

      sqlserver_tsql{ "v79073_database_audit_maintainers_add_member_${instance}_${database}_${audit_user}":
        instance => $instance,
        database => $database,
        command  => $sql_add,
        require  => Sqlserver::Config[$instance],
        onlyif   => "IF NOT EXISTS (SELECT dp2.name [user] FROM sys.database_role_members drm
FULL OUTER JOIN sys.database_principals dp1 ON drm.role_principal_id = dp1.principal_id
LEFT OUTER JOIN sys.database_principals dp2 ON drm.member_principal_id = dp2.principal_id
WHERE dp1.name = 'DATABASE_AUDIT_MAINTAINERS' AND dp1.type = 'R' AND dp2.name = '${audit_user}' )
THROW 50002, 'The ${audit_user} user not in database_audit_maintainers role.', 10",
      }
    }

    # Step 3: Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements
    #         to remove CONTROL DATABASE permission from logins that do not need it.
    #         The database_principal cannot be a fixed database role or a server principal.

    $fact_array = $facts['sqlserver_audit_maintainer_roles_and_users']

    $fact_array.each |$fact_hash| {
      #if downcase($db_hash['database_name']) == downcase($database) {
      unless empty($fact_hash['Principal']) and empty($fact_hash['Role']) {
        $principal = $fact_hash['Principal']
        $role = $fact_hash['Role']
        $permission = $fact_hash['GrantedPermission']
        # ALTER ROLE SQL...
        # NOTE: cannot use the special principal 'dbo'
        if !empty($principal) and !empty($role) and $role=='db_owner' and downcase($principal)!='dbo' {
          $user = $principal
          $sql = "ALTER ROLE db_owner DROP MEMBER ${user};"

          ::secure_sqlserver::log { "V-79073: alter role on ${instance}\\${database}: sql = \n${sql}": }

          sqlserver_tsql{ "v79073_database_audit_maintainers_drop_member_${user}_on_${instance}_${database}":
            instance => $instance,
            database => $database,
            command  => $sql,
            require  => Sqlserver::Config[$instance],
          }
        }

        # REVOKE CONTROL DATABASE SQL...
        if !empty($principal) and downcase($principal)!='dbo' and !empty($permission) and ($permission[0,7]=='CONTROL' or $permission=='ALTER ANY DATABASE AUDIT') { #lint:ignore:140chars
          $user = $principal
          $sql = "REVOKE ${permission} FROM ${user};"

          ::secure_sqlserver::log { "V-79073: revoke control database permission for ${user} on ${instance}\\${database}: sql = \n${sql}": }

          sqlserver_tsql{ "v79073_database_audit_maintainers_revoke_permission_for_${user}_on_${instance}_${database}":
            instance => $instance,
            database => $database,
            command  => $sql,
            require  => Sqlserver::Config[$instance],
          }
        }
      }
    }
  }
}
