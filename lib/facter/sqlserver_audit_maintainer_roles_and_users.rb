# sqlserver_audit_maintainer_roles_and_users.rb
#
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
#
# Review the database roles and individual users that have the following role memberships,
# all of which enable the ability to create and maintain audit specifications.
#   db_owner
#
# Review the database roles and individual users that have the following permissions,
# all of which enable the ability to create and maintain audit definitions.
#   ALTER ANY DATABASE AUDIT
#   CONTROL
#
# Dependencies:
# v79073
#
# @return   An array of hashes containing audit-related users/roles/permissions.
# @example
#
require 'sqlserver_client'

Facter.add('sqlserver_audit_maintainer_roles_and_users') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT DP.Name AS 'Principal', R.name AS 'Role', DbPerm.permission_name AS 'GrantedPermission'
FROM sys.database_principals DP
LEFT OUTER JOIN sys.database_permissions DbPerm ON DP.principal_id = DbPerm.grantee_principal_id
LEFT OUTER JOIN sys.database_role_members DRM ON DP.principal_id = DRM.member_principal_id
INNER JOIN sys.database_principals R ON DRM.role_principal_id = R.principal_id
WHERE DbPerm.permission_name IN ('CONTROL DATABASE','ALTER ANY DATABASE AUDIT')
OR R.name IN ('db_owner')"

    Puppet.debug "sqlserver_audit_maintainer_roles_and_users.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
