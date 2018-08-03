# sqlserver_databases_trustworthy_property.rb
#
# Determine if the trustworthy property is set on the database.
# SQL Server provides the ability for high privileged accounts to impersonate users
# in a database using the TRUSTWORTHY feature. This will allow members of the
# fixed database role to impersonate any user within the database.
#
# @return   An array of hashes containing each database name and whether trustworthy is set.
# @example
#           [ { database => 'master', is_trustworthy_on => false },
#             {  database => 'tempdb', is_trustworthy_on => false },
#             {  database => 'model', is_trustworthy_on => false },
#             {  database => 'msdb', is_trustworthy_on => true },
#           ]
#
Facter.add('sqlserver_databases_trustworthy_property') do
  confine operatingsystem: :windows
  setcode do
    databases = []
    sql = "SELECT name as database_name, SUSER_SNAME(owner_sid) AS database_owner, is_trustworthy_on FROM sys.databases"
    Puppet.debug "sqlserver_databases_trustworthy_property.rb sql...\n#{sql}"
    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    databases = client.data
    client.close unless client.nil? || client.closed?
    databases
  end
end
