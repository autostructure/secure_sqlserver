# v79133.pp
# SQL Server must be configured to generate audit records for DoD-defined
# auditable events within all DBMS/database components.
#
# DoD has defined the list of events for which SQL Server will provide an
# audit record generation capability as the following:
# (i) Successful and unsuccessful attempts to access, modify, or delete privileges,
#     security objects, security levels, or categories of information
#     (e.g., classification levels);
# (ii) Access actions, such as successful and unsuccessful logon attempts,
#      privileged activities, or other system-level access, starting and ending
#      time for user access to the system, concurrent logons from different workstations,
#      successful and unsuccessful accesses to objects, all program initiations,
#      and all direct access to the information system; and
# (iii) All account creation, modification, disabling, and termination actions.
#
class secure_sqlserver::stig::v79133 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {

  ##TODO:
  # 1. Check w/Charlie about necessity of auditpol/secpol setup
  # 2. Ask about audit criteria i, ii, iii above.

  # setup auditable events
  include ::secure_sqlserver::auditpol_setup
  $auditable_events = $facts['sqlserver_v79131_auditable_events']

}
