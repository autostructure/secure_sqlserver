# This class manages V-67361
# Where SQL Server Audit is in use at the database level, SQL Server must allow
# only the ISSM (or individuals or roles appointed by the ISSM) to select which
# auditable events are to be audited at the database level.
class secure_postgres::stig::v67361 (
  Boolean $enforced = false,
) {

  # Create a database role specifically for audit maintainers,
  # and give it permission to maintain audits, without granting it unnecessary permissions:
  # (The role name used here is an example; other names may be used.)
  $sql = 'USE <database name>;
GO
CREATE ROLE DATABASE_AUDIT_MAINTAINERS;
GO
GRANT ALTER ANY DATABASE AUDIT TO DATABASE_AUDIT_MAINTAINERS;
GO'

  # Use REVOKE and/or DENY and/or ALTER ROLE ... DROP MEMBER ...
  # statements to remove the ALTER ANY DATABASE AUDIT permission from all users.

  # Then, for each authorized database user, run the statement:
  $sql = 'ALTER ROLE DATABASE_AUDIT_MAINTAINERS ADD MEMBER <user name> ;
GO'

# Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ...
# statements to remove CONTROL DATABASE permission from logins that do not need it.

}
