# sqlserver_authentication_mode.rb
#
# @return   'Windows Authentication' or 'Windows and SQL Server Authentication'
#
# Dependencies:
# v79061
#
require 'sqlserver_client'

Facter.add('sqlserver_authentication_mode') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT CASE serverproperty('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'Windows and SQL Server Authentication' END"

    Puppet.debug "sqlserver_authentication_mode.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset

  end
end
