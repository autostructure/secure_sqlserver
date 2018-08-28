# sqlserver_symmetric_keys.rb
#
# @return   An array of strings representing symmetric encryption key names.
# @example  ['##MS_ServiceMasterKey##']
#
# Dependencies:
# v79087
#
require 'sqlserver_client'

Facter.add('sqlserver_symmetric_keys') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT name FROM master.sys.symmetric_keys"

    Puppet.debug "sqlserver_symmetric_keys.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
