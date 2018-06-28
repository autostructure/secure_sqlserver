# sqlserver_v79135_audit_permission_findings.rb
#
# Review the server roles and individual logins that have the following role memberships,
# all of which enable the ability to create and maintain audit definitions:
# sysadmin
# dbcreator
#
# @return   An array of hashes representing role and user name data.
# @example  Below is a result that includes a permission and a role:
#           [{
#             Securable Class => "SERVER",
#             Securable => "windows-server-hostname",
#             Grantee => "##MS_PolicySigningCertificate##",
#             Grantee Type => "CERTIFICATE_MAPPED_LOGIN",
#             Permission => "CONTROL SERVER",
#             State => "GRANT",
#             Grantor => "sa",
#             Grantor Type => "SQL_LOGIN",
#             Role Name =>
#           },
#           {
#             Securable Class => "SERVER_PRINCIPAL",
#             Securable => "NT Service\MSSQLSERVER",
#             Grantee => ,
#             Grantee Type => ,
#             Permission => ,
#             State => ,
#             Grantor => ,
#             Grantor Type => ,
#             Role Name => "sysadmin"
#           }]
#
##TODO:
#       1. REVOKE CONTROL SERVER FROM <SERVER_NAME>
#          Results in an error: <SERVER_NAME> is not a login
#          Format as REVOKE on OBJECT?
#       2. Don't have permission to remove 'sa','NT SERVICE\MSSQLSERVER', or 'NT SERVICE\SQLWriter' from 'sysadmin' role.
#          Add logic to skip 'sa'
#          Skip other two as well?  Or not?
#
require 'sqlserver_client'

Facter.add('sqlserver_v79135_audit_permission_findings') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT-- DISTINCT
CASE
WHEN SP.class_desc IS NOT NULL THEN
CASE
WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER'
WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)'
ELSE SP.class_desc
END
WHEN E.name IS NOT NULL THEN 'ENDPOINT'
WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER'
WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)'
WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL'
ELSE '???'
END AS [Securable Class],
CASE
WHEN E.name IS NOT NULL THEN E.name
WHEN S.name IS NOT NULL THEN S.name
WHEN P.name IS NOT NULL THEN P.name
ELSE '???'
END AS [Securable],
P1.name AS [Grantee],
P1.type_desc AS [Grantee Type],
sp.permission_name AS [Permission],
sp.state_desc AS [State],
P2.name AS [Grantor],
P2.type_desc AS [Grantor Type],
R.name AS [Role Name]
FROM
sys.server_permissions SP
INNER JOIN sys.server_principals P1
ON P1.principal_id = SP.grantee_principal_id
INNER JOIN sys.server_principals P2
ON P2.principal_id = SP.grantor_principal_id

FULL OUTER JOIN sys.servers S
ON SP.class_desc = 'SERVER'
AND S.server_id = SP.major_id

FULL OUTER JOIN sys.endpoints E
ON SP.class_desc = 'ENDPOINT'
AND E.endpoint_id = SP.major_id

FULL OUTER JOIN sys.server_principals P
ON SP.class_desc = 'SERVER_PRINCIPAL'
AND P.principal_id = SP.major_id

FULL OUTER JOIN sys.server_role_members SRM
ON P.principal_id = SRM.member_principal_id

LEFT OUTER JOIN sys.server_principals R
ON SRM.role_principal_id = R.principal_id
WHERE sp.permission_name IN ('ALTER ANY SERVER AUDIT','CONTROL SERVER','ALTER ANY DATABASE','CREATE ANY DATABASE')
OR R.name IN ('sysadmin','dbcreator')"

    Puppet.debug "sqlserver_v79135_dbcreator_sysadmin_members.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
