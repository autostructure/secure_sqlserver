# v79075.pp
#
# This class manages DISA STIG vulnerability: V-79075
# SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers.
#
define secure_sqlserver::stig::v79075 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    # $sql = "SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
    # CASE class
    # WHEN 0 THEN DB_NAME()
    # WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
    # WHEN 3 THEN SCHEMA_NAME(major_id)
    # ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
    # END AS securable_name, DP.state_desc, DP.permission_name
    # FROM sys.database_permissions DP
    # JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
    # LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','','RF','PC','IF','FN','TF','U')
    # WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    #
    # SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
    # FROM sys.database_principals R
    # JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
    # JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
    # WHERE R.name IN ('db ddladmin','db_owner')
    # AND M.name != 'dbo'"

    ::secure_sqlserver::log { "V-79075: ${instance}\\${database}: sql=${sql}":
      loglevel => notice,
    }

    $role_array = $facts['sqlserver_v79075_software_library_admin_roles']
    $user_array = $facts['sqlserver_v79075_software_library_admin_users']

    $role_array.each |$fact_hash| {
      unless empty($fact_hash['Principal']) or empty($fact_hash['Role']) {
        $user = $fact_hash['Principal']
        $role = $fact_hash['Role']
        $sql = "ALTER ROLE ${role} DROP MEMBER ${user};"

        ::secure_sqlserver::log { "V-79111: drop user, ${user}, from role, ${role}, on ${instance}\\${database}: sql = \n${sql}": }
        sqlserver_tsql{ "v79075_drop_member_${user}_from_role_${role}_on_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      }
    }

    $user_array.each |$fact_hash| {
      unless empty($fact_hash['Principal']) or empty($fact_hash['Permission']) {
        $user = $fact_hash['Principal']
        $object = $fact_hash['Object']
        $permission = $fact_hash['Permission']
        $sql = "REVOKE ${permission} ON ${object} TO ${user};"

        ::secure_sqlserver::log { "V-79075: drop permission, ${permission}, from user, ${user}, on object ${object}, in ${instance}\\${database}: sql = \n${sql}": }
        sqlserver_tsql{ "v79075_drop_permission_${permission}_from_user_${user}_on_${object}_in_${instance}_${database}":
          instance => $instance,
          database => $database,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      }
    }

  }
}
