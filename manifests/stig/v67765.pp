# This class manages V-67765
# Where SQL Server Trace is in use for auditing purposes,
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM)
# to select which auditable events are to be traced.
class secure_sqlserver::stig::v67765 (
  Boolean $enforced = false,
) {

  # Create a server role specifically for audit maintainers,
  # and give it permission to maintain traces,
  # without granting it unnecessary permissions:
  #USE master;
  #GO
  #CREATE SERVER ROLE SERVER_AUDIT_MAINTAINERS;
  #GO
  #GRANT ALTER TRACE TO SERVER_AUDIT_MAINTAINERS;
  # -- Next line only if 'required':
  #GRANT CREATE TRACE EVENT NOTIFICATION TO SERVER_AUDIT_MAINTAINERS;
  #GO
  # (The role name used here is an example; other names may be used.)

  # Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ...
  # statements to remove the ALTER TRACE and CREATE TRACE EVENT NOTIFICATION permissions
  # from all logins.

  # Then, for each authorized login, run the 'statement':
  #ALTER SERVER ROLE SERVER_AUDIT_MAINTAINERS ADD MEMBER <login name>;
  #GO

}
