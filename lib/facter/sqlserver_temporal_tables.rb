#!/usr/bin/env ruby -wKU
# sqlserver_temporal_tables.rb
#
require 'sqlserver_client'

Facter.add('sqlserver_temporal_tables') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc,
SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
FROM sys.tables T
JOIN sys.tables H ON T.history_table_id = H.object_id
WHERE T.temporal_type != 0
ORDER BY schema_name, table_name"

    Puppet.debug "sqlserver_temporal_tables.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
