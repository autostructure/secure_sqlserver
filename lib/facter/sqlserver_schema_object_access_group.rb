# sqlserver_schema_object_access_group.rb
#
# SQL Server must be configured to generate audit records for DoD-defined
# auditable events within all DBMS/database components.
#
# Dependencies:
# v79137
#
# @return   An array of strings representing the SCHEMA_OBJECT_ACCESS_GROUP records.
# @example
#
require 'sqlserver_client'

Facter.add('sqlserver_schema_object_access_group') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT a.name AS 'AuditName',
       s.name AS 'SpecName',
       d.audit_action_name AS 'ActionName',
       d.audited_result AS 'Result'
  FROM sys.server_audit_specifications s
  JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
  JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
 WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'"

    Puppet.debug "sqlserver_schema_object_access_group.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
