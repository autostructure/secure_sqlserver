#!/usr/bin/env ruby -wKU
# sqlserver_v79075_software_library_admin_users.rb
#
#
require 'sqlserver_client'

Facter.add('sqlserver_v79075_software_library_admin_users') do
  confine operatingsystem: :windows
  setcode d o

    # sql = "SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
    # CASE class
    # WHEN 0 THEN DB_NAME()
    # WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
    # WHEN 3 THEN SCHEMA_NAME(major_id)
    # ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
    # END AS securable_name, DP.state_desc, DP.permission_name
    # FROM sys.database_permissions DP
    # JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
    # LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','','RF','PC','IF','FN','TF','U')
    # WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)"

    sql = "SELECT P.type_desc AS principal_type, P.name AS Principal, O.type_desc,
CASE class
WHEN 0 THEN DB_NAME()
WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
WHEN 3 THEN SCHEMA_NAME(major_id)
ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
END AS Object, DP.state_desc, DP.permission_name AS Permission
FROM sys.database_permissions DP
JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','','RF','PC','IF','FN','TF','U')
WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)"

    Puppet.debug "sqlserver_v79075_software_library_admin_users.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
