#!/usr/bin/env ruby -wKU
# sqlserver_v79075_software_library_admin_roles.rb
#
require 'sqlserver_client'

Facter.add('sqlserver_v79075_software_library_admin_roles') do
  confine operatingsystem: :windows
  setcode do

    # sql = "SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
    # FROM sys.database_principals R
    # JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
    # JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
    # WHERE R.name IN ('db ddladmin','db_owner')
    # AND M.name != 'dbo'"

    sql = "SELECT R.name AS Role, M.type_desc AS principal_type, M.name AS Principal
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
WHERE R.name IN ('db ddladmin','db_owner')
AND M.name != 'dbo'"

    Puppet.debug "sqlserver_v79075_software_library_admin_roles.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
