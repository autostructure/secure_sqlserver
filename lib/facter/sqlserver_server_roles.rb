# sqlserver_server_roles.rb
#
# The 'sqlserver_server_roles' fact returns an array list of all server roles.
# Two types of roles are reported:
# 'server roles', 'database roles'
# However, 'application roles' are not included.
#
# @return   An array of strings representing server roles.
# @example  ['bulkadmin', 'dbcreator', 'diskadmin', 'processadmin', 'public', 'securityadmin', 'serveradmin', 'setupadmin', 'sysadmin']
#
Facter.add('sqlserver_server_roles') do
  confine operatingsystem: :windows
  setcode do

    # TODO: remove hard-coded return result and query the database.

    roles = []

    $sql_detail = "SELECT srm.role_principal_id, sp1.name, srm.member_principal_id, sp2.name. sp1.type
    FROM sys.server_role_members srm
    FULL OUTER JOIN sys.server_principals sp1
    ON srm.role_principal_id = sp1.principal_id
    LEFT OUTER JOIN sys.server_principals sp2
    ON srm.member_principal_id = sp2.principal_id
    WHERE sp1.type = 'R'"

    begin

      # system databases
      # select name fom sys.sysdatabases where dbid <5
      # user databases
      # select name fom sys.sysdatabases where dbid >4
      sql = "SELECT name FROM sys.server_principals WHERE type='R';"

      Puppet.debug "sqlserver_server_roles.rb sql...\n#{sql}"

      client = SqlServerClient.new
      client.open
      client.column(sql)
      # An ADO Recordset's GetRows method returns an array
      # of columns, so we'll use the transpose method to
      # convert it to an array of rows
      roles = client.data
      client.close unless client.nil? || client.closed?

      #roles = %w[bulkadmin dbcreator diskadmin processadmin public securityadmin serveradmin setupadmin sysadmin]

    rescue StandardError => e
      Puppet.debug "Facter: sqlserver_server_roles.rb error occurred: #{e}"
    end

    roles
    
  end
end
