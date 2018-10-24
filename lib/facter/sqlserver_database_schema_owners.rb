# sqlserver_database_schema_owners.rb
#
# @return   A hash with the database name and its owner.
# @example
#           [ { database => 'master', owner => dbo },
#             {  database => 'tempdb', owner => dbo },
#             {  database => 'model', owner => dbo },
#             {  database => 'msdb', owner => dbo },
#           ]
# @dependencies
#           v79077
#
Facter.add('sqlserver_database_schema_owners') do
  confine operatingsystem: :windows
  setcode do
    ret = []
    sql = "SELECT S.name AS schema_name, P.name AS owning_principal
FROM sys.schemas S
JOIN sys.database_principals P ON S.principal_id = P.principal_id
ORDER BY schema_name"
    Puppet.debug "sqlserver_database_schema_owners.rb sql...\n#{sql}"
    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    ret = client.data
    client.close unless client.nil? || client.closed?
    ret
  end
end
