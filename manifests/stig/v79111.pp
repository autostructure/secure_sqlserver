# v79111.pp
#
# This class manages DISA STIG vulnerability: V-79111
# SQL Server must enforce access restrictions associated with changes to the configuration of the database(s).
#
# Fact SQL:
#
# sql = "SELECT p.name AS Principal,
# p.type_desc AS Type,
# r.name AS Role
# FROM sys.database_principals p
# INNER JOIN sys.database_role_members rm ON p.principal_id = rm.member_principal_id
# INNER JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
# WHERE r.name = 'db_owner'
# UNION ALL
# SELECT l.name AS Principal,
# l.type_desc AS Type,
# 'dbo' AS Role
# FROM sys.databases d
# INNER JOIN sys.server_principals l ON d.owner_sid = l.sid
# WHERE d.name = DB_NAME()"
#
define secure_sqlserver::stig::v79111 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    $fact_array = $facts['sqlserver_database_roles_and_users']

    unless empty($fact_array) {
      $fact_array.each |$fact_hash| {
        # TODO: write logic for msdb owner...dropping dbo from db_owners causes error (in msdb only?)...cover all dbo for now.
        # received sql error trying to drop 'sa' from 'dbo' role...
        unless empty($fact_hash['Principal']) or empty($fact_hash['Role']) or downcase($fact_hash['Principal'])=='sa' or downcase($fact_hash['Principal'])=='dbo' {

          $user = $fact_hash['Principal']
          $role = $fact_hash['Role']
          $sql = "ALTER ROLE ${role} DROP MEMBER ${user};"

          ::secure_sqlserver::log { "V-79111: drop user, ${user}, from role, ${role}, on ${instance}\\${database}: sql = \n${sql}": }

          sqlserver_tsql{ "v79111_database_owners_drop_member_${user}_from_role_${role}_on_${instance}_${database}":
            instance => $instance,
            database => $database,
            command  => $sql,
            require  => Sqlserver::Config[$instance],
          }

        }
      }
    }
    # Set the owner of the database to an authorized login:
    # https://msdn.microsoft.com/en-us/library/ms187359.aspx

    $new_db_owner =lookup('secure_sqlserver::new_database_owner')[$database]

    # TODO: write logic for msdb owner?!?!

    unless empty($new_db_owner) or $database in ['master','model','msdb','tempdb'] {

      $sql_check = "IF NOT EXISTS (SELECT name FROM master.sys.syslogins WHERE name = '${new_db_owner}') THROW 50002, 'Missing login for alter authorization.',10"
      $sql_login = "CREATE LOGIN [${new_db_owner}] FROM WINDOWS WITH DEFAULT_DATABASE = '${database}'"

      ::secure_sqlserver::log { "V-79111: create login for ${new_db_owner} on ${instance}\\${database}: sql = \n${sql}": }

      sqlserver_tsql{ "v79111_create_login_for_new_db_owner_${new_db_owner}_on_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql_login,
        require  => Sqlserver::Config[$instance],
        onlyif   => $sql_check,
      }

      $sql = "ALTER AUTHORIZATION ON database::${database} TO ${new_db_owner};"

      ::secure_sqlserver::log { "V-79111: alter authorization set db_owner to ${new_db_owner} on ${instance}\\${database}: sql = \n${sql}": }

      sqlserver_tsql{ "v79111_alter_authorization_set_db_owner_to_${new_db_owner}_on_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql,
        require  => Sqlserver::Config[$instance],
      }

    }

  }

}
