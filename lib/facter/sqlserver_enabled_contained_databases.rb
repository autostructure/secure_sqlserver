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
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset['config_value']) ? true : false

  end
end
