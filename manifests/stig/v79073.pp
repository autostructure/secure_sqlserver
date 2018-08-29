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
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    # Step 1: Create new audit role...

    $sql_create = "USE ${database}; CREATE ROLE DATABASE_AUDIT_MAINTAINERS; GRANT ALTER ANY DATABASE AUDIT TO DATABASE_AUDIT_MAINTAINERS;"

    ::secure_sqlserver::log { "V-79073: create audit role on ${instance}\\${database}: sql = \n${sql_create}": }
    sqlserver_tsql{ "v79073_create_database_audit_maintainers_${instance}_${database}":
      instance => $instance,
      database => $database,
      command  => $sql_create,
      require  => Sqlserver::Config[$instance],
      onlyif   => "IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DATABASE_AUDIT_MAINTAINERS' and type='R') THROW 50001, 'Missing DATABASE_AUDIT_MAINTAINERS role.', 10",
    }

    # Step 2: Add audit maintainer user to new DATABASE_AUDIT_MAINTAINERS role...

    $audit_user = lookup('secure_sqlserver::audit_maintainer_username')[$database]

    unless empty($audit_user) {

      $sql_new_user = "CREATE USER ${audit_user} WITHOUT LOGIN"
      # You need the single quotes around the username or t-sql thinks it a column...
      $sql_check = "IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name='${audit_user}') THROW 50002, 'Missing auditing user.',10"

      ::secure_sqlserver::log { "V-79073: create audit maintainer user '${audit_user}' on ${instance}\\${database}: sql = \n${sql_new_user}": }

      sqlserver_tsql{ "v79073_database_audit_maintainers_create_user_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_new_user,
        require  => Sqlserver::Config[$instance],
        onlyif   => "IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name='${audit_user}') THROW 50002, 'Missing auditing user.',10",
      }

      $sql_add = "ALTER ROLE DATABASE_AUDIT_MAINTAINERS ADD MEMBER ${audit_user};"

      ::secure_sqlserver::log { "V-79073: add member to role on ${instance}\\${database}: sql = \n${sql_add}": }

      sqlserver_tsql{ "v79073_database_audit_maintainers_add_member_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_add,
        require  => Sqlserver::Config[$instance],
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
          # sqlserver_tsql{ "v79073_database_audit_maintainers_drop_member_${user}_on_${instance}_${database}":
          #   instance => $instance,
          #   database => $database,
          #   command  => $sql,
          #   require  => Sqlserver::Config[$instance],
          # }
        }
        # REVOKE CONTROL DATABASE SQL...
        $permission_left = $permission[0,3]
        ::secure_sqlserver::log { "V-79073: permission[0,3]=${permission_left} on ${instance}\\${database}\\${principal}": }
        if !empty($principal) and downcase($principal)!='dbo' and !empty($permission) and ($permission[0,6]=='CONTROL' or $permission=='ALTER ANY DATABASE AUDIT') {
          $user = $principal
          $sql = "REVOKE ${permission} FROM ${user};"
          ::secure_sqlserver::log { "V-79073: revoke control database permission for ${user} on ${instance}\\${database}: sql = \n${sql}": }
          # sqlserver_tsql{ "v79073_database_audit_maintainers_revoke_permission_for_${user}_on_${instance}_${database}":
          #   instance => $instance,
          #   database => $database,
          #   command  => $sql,
          #   require  => Sqlserver::Config[$instance],
          # }
        }
      }
    }

  }

}
