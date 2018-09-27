#!/usr/bin/env ruby -wKU
# sqlserver_temporal_tables.rb
#
# @return hash of arrays: keys=databases, values=array of strings representing a SQL Server temporal table formatted as: SCHEMA_NAME.
# NOTE: This fact is used by database level hardening.
#       So must provide fact BY DATABASE.
#
# SQL from STIG
# -------------
# SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc,
# SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
# FROM sys.tables T
# JOIN sys.tables H ON T.history_table_id = H.object_id
# WHERE T.temporal_type != 0
# ORDER BY schema_name, table_name
#
require 'sqlserver_client'

Facter.add('sqlserver_temporal_tables') do
  confine operatingsystem: :windows
  setcode do

    ret = {}
    databases = Facter.value(:sqlserver_databases)
    databases.each do |db|

      sql = "USE #{db}; SELECT SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
  FROM sys.tables T
  JOIN sys.tables H ON T.history_table_id = H.object_id
  WHERE T.temporal_type != 0
  ORDER BY 1;"

      Puppet.debug "sqlserver_temporal_tables.rb sql...\n#{sql}"

      client = SqlServerClient.new
      client.open
      client.column(sql)
      resultset = client.data
      client.close unless client.nil? || client.closed?
      ret[db] = resultset

    end

    ret

  end
end
