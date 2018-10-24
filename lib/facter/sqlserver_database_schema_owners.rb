# sqlserver_database_schema_owners.rb
#
# @return   A hash of databases containing an array of hashes with each schema and owner.
# @example
#           {
#            "master" => [ { "owner" => "db_owner", "schema_name" => "db_owner"},
#                          { "owner" => "dbo", "schema_name" => "dbo" },
#                          { "owner" => "guest", "schema_name" => "guest" },
#                          { "owner" => "INFORMATION_SCHEMA", "schema_name" => "INFORMATION_SCHEMA" },
#                          { "owner" => "sys", "schema_name" => "sys"}
#                        ],
#            "model"  => [ { "schema" => "dbo", "owner" => "dbo" } ],
#            "msdb"   => [ { "schema" => "dbo", "owner" => "dbo" } ],
#            "tempdb" => [ { "schema" => "dbo", "owner" => "dbo" } ],
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
      sql = "SELECT S.name AS schema_name, P.name AS owner
FROM [#{db}].sys.schemas S
JOIN [#{db}].sys.database_principals P ON S.principal_id = P.principal_id
ORDER BY schema_name"

      # NOTE: USE <database> doesn't work in-line w/SELECT in ADO:
      #sql = "USE #{db}; SELECT S.name AS schema_name, P.name AS owner
      #FROM sys.schemas S
      #JOIN sys.database_principals P ON S.principal_id = P.principal_id
      #ORDER BY schema_name"

      Puppet.debug "sqlserver_database_schema_owners.rb sql...\n#{sql}"
      client = SqlServerClient.new
      client.open
      client.hasharray(sql)
      ret[db] = client.data
      client.close unless client.nil? || client.closed?
    end
    ret
  end
end
