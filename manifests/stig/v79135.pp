# v79135.pp
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM)
# to select which auditable events are to be audited.
#
# This is a separation of roles.
# Separating the audit administration from other administration (like blanket sysadmin).
#
class secure_sqlserver::stig::v79135 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {

  $dbcreator_sysadmin_members = $facts['sqlserver_v79135_dbcreator_sysadmin_members']

  # STEP #1: Get...

  # Obtain the list of approved audit maintainers from the system documentation.

  # Review the server roles and individual logins that have the following role memberships, all of which enable the ability to create and maintain audit definitions.

  # sysadmin
  # dbcreator

  # Review the server roles and individual logins that have the following permissions, all of which enable the ability to create and maintain audit definitions.

  # ALTER ANY SERVER AUDIT
  # CONTROL SERVER
  # ALTER ANY DATABASE
  # CREATE ANY DATABASE

  # Use the following query to determine the roles and logins that have the listed permissions:

  # SELECT-- DISTINCT
  # CASE
  # WHEN SP.class_desc IS NOT NULL THEN
  # CASE
  # WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER'
  # WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)'
  # ELSE SP.class_desc
  # END
  # WHEN E.name IS NOT NULL THEN 'ENDPOINT'
  # WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER'
  # WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)'
  # WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL'
  # ELSE '???'
  # END AS [Securable Class],
  # CASE
  # WHEN E.name IS NOT NULL THEN E.name
  # WHEN S.name IS NOT NULL THEN S.name
  # WHEN P.name IS NOT NULL THEN P.name
  # ELSE '???'
  # END AS [Securable],
  # P1.name AS [Grantee],
  # P1.type_desc AS [Grantee Type],
  # sp.permission_name AS [Permission],
  # sp.state_desc AS [State],
  # P2.name AS [Grantor],
  # P2.type_desc AS [Grantor Type],
  # R.name AS [Role Name]
  # FROM
  # sys.server_permissions SP
  # INNER JOIN sys.server_principals P1
  # ON P1.principal_id = SP.grantee_principal_id
  # INNER JOIN sys.server_principals P2
  # ON P2.principal_id = SP.grantor_principal_id
  #
  # FULL OUTER JOIN sys.servers S
  # ON SP.class_desc = 'SERVER'
  # AND S.server_id = SP.major_id
  #
  # FULL OUTER JOIN sys.endpoints E
  # ON SP.class_desc = 'ENDPOINT'
  # AND E.endpoint_id = SP.major_id
  #
  # FULL OUTER JOIN sys.server_principals P
  # ON SP.class_desc = 'SERVER_PRINCIPAL'
  # AND P.principal_id = SP.major_id
  #
  # FULL OUTER JOIN sys.server_role_members SRM
  # ON P.principal_id = SRM.member_principal_id
  #
  # LEFT OUTER JOIN sys.server_principals R
  # ON SRM.role_principal_id = R.principal_id
  # WHERE sp.permission_name IN ('ALTER ANY SERVER AUDIT','CONTROL SERVER','ALTER ANY DATABASE','CREATE ANY DATABASE')
  # OR R.name IN ('sysadmin','dbcreator')
  #
  # If any of the logins, roles, or role memberships returned have permissions that are not documented,
  # or the documented audit maintainers do not have permissions, this is a finding.




  # STEP #2: Fix...

  # Create a server role specifically for audit maintainers and give it permission to
  # maintain audits without granting it unnecessary permissions (the role name used
  # here is an example; other names may be used):
  #
  # CREATE SERVER ROLE SERVER_AUDIT_MAINTAINERS;
  # GO
  # GRANT ALTER ANY SERVER AUDIT TO SERVER_AUDIT_MAINTAINERS;
  # GO

  # Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements
  # to remove the ALTER ANY SERVER AUDIT permission from all logins. Then, for each authorized login, run the statement:
  # ALTER SERVER ROLE SERVER_AUDIT_MAINTAINERS ADD MEMBER;
  # GO

  # Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ...
  # statements to remove CONTROL SERVER, ALTER ANY DATABASE and CREATE ANY DATABASE permissions from logins that do not need them.

}
