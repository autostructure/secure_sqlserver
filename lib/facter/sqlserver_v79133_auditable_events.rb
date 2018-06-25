# sqlserver_v79133_auditable_events.rb
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
# In a high security environment, the Windows Security log is the appropriate
# location to write events that record object access. Other audit locations
# are supported but are more subject to tampering.
# Source:
# https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/write-sql-server-audit-events-to-the-security-log?view=sql-server-2017
#
# @return   An array of hashes representing audit event rule records.
# @example
#
require 'sqlserver_client'

Facter.add('sqlserver_v79131_shared_accounts') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT name AS 'audit_name'
                , status_desc AS 'audit_status'
                , audit_file_path AS 'current_audit_file'
             FROM sys.dm_server_audit_status"



    Puppet.debug "sqlserver_v79131_shared_accounts.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.simple_array(sql)
    # An ADO Recordset's GetRows method returns an array
    # of columns, so we'll use the transpose method to
    # convert it to an array of rows
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
