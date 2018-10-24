# sqlserver_database_schema_owners.rb
#
# @return   A hash of databases containing a hash with each schema and its owner.
# @example
#           {
#            master => { schema => 'dbo', owner => dbo },
#            tempdb => { schema => 'dbo', owner => dbo },
#            model  => { schema => 'dbo', owner => dbo },
#            msdb   => { schema => 'dbo', owner => dbo },
#           }
#
# @dependencies
#           v79077
#
Facter.add('sqlserver_database_schema_owners') do
  confine operatingsystem: :windows
  setcode do
    ret = {}

    # loop through databases in sqlserver_databases
    databases = Facter.value(:sqlserver_databases)
    databases.each do |db|

      sql = "USE #{db}; SELECT S.name AS schema, P.name AS owner
FROM sys.schemas S
JOIN sys.database_principals P ON S.principal_id = P.principal_id
ORDER BY schema_name"
      Puppet.debug "sqlserver_database_schema_owners.rb sql...\n#{sql}"
      client = SqlServerClient.new
      client.open
      client.hasharray(sql)
      resultset = client.data
      client.close unless client.nil? || client.closed?
      ret[db] = resultset
    end
  end
  ret
end
