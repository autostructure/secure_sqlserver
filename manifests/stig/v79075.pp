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

    $sql = "SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
CASE class
WHEN 0 THEN DB_NAME()
WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
WHEN 3 THEN SCHEMA_NAME(major_id)
ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
END AS securable_name, DP.state_desc, DP.permission_name
FROM sys.database_permissions DP
JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','','RF','PC','IF','FN','TF','U')
WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)

SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
WHERE R.name IN ('db ddladmin','db_owner')
AND M.name != 'dbo'"

    ::secure_sqlserver::log { "V-79075: ${instance}\\${database}: sql=${sql}":
      loglevel => notice,
    }

  }
}
