# sqlserver_database_roles_and_users.rb
#
# Dependencies:
# v79111
#
# @return   An array of hashes containing database roles/users.
# @example
#
require 'sqlserver_client'

Facter.add('sqlserver_database_roles_and_users') do
  confine operatingsystem: :windows
  setcode do

    # TODO: may have to query each database separate and UNION ALL the results.
    #       if no database context is set, you might get the master database results instead...
    sql = "SELECT p.name AS Principal,
p.type_desc AS Type,
r.name AS Role
FROM sys.database_principals p
INNER JOIN sys.database_role_members rm ON p.principal_id = rm.member_principal_id
INNER JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'db_owner'
UNION ALL
SELECT l.name AS Principal,
l.type_desc AS Type,
'dbo' AS Role
FROM sys.databases d
INNER JOIN sys.server_principals l ON d.owner_sid = l.sid
WHERE d.name = DB_NAME()"

    Puppet.debug "sqlserver_audit_maintainer_roles_and_users.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
