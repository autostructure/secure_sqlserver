# sqlserver_certificates.rb
#
# @return   A hash listing certificates by database.
#
# Dependencies:
# v79089
#
require 'sqlserver_client'

Facter.add('sqlserver_certificates') do
  confine operatingsystem: :windows
  setcode do

    ret = {}
    databases = Facter.value(:sqlserver_databases)
    databases.each do |db|

      sql = "SELECT name FROM [#{db}].sys.certificates ORDER BY 1;"

      Puppet.debug "sqlserver_certificates.rb sql...\n#{sql}"

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
