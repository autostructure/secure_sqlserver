# sqlserver_enabled_contained_databases.rb
#
# @return   true/false
#
# Dependencies:
# v79061
#
require 'sqlserver_client'

Facter.add('sqlserver_enabled_contained_databases') do
  confine operatingsystem: :windows
  setcode do

    sql = "EXEC sp_configure 'contained database authentication'"

    Puppet.debug "sqlserver_enabled_contained_databases.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    Puppet.debug "resultset[0]=#{resultset[0]}"
    Puppet.debug "resultset[0]['config_value']=#{resultset[0]['config_value']}"
    resultset[0]['config_value']==1 ? true : false
  end
end
