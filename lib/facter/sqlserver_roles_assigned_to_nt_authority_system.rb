# The 'sqlserver_roles_assigned_to_nt_authority_system' fact returns an array list
# of all roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# All types of roles are reported including 'server roles', 'database roles', and 'application roles'.
#
# @return   An array of strings representing roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# @example  ['bulkadmin', 'dbcreator', 'diskadmin', 'processadmin', 'public', 'securityadmin', 'serveradmin', 'setupadmin', 'sysadmin']
#
require 'sqlserver_client'

Facter.add('sqlserver_roles_assigned_to_nt_authority_system') do
  confine operatingsystem: :windows
  setcode do

    role_array = []

    ddl1 = "ALTER ROLE "
    ddl2 = " REMOVE MEMBER 'NT AUTHORITY\\SYSTEM'"

    sql = "SELECT sp1.name
    FROM sys.server_role_members srm
    LEFT JOIN sys.server_principals sp1
    ON srm.role_principal_id = sp1.principal_id
    LEFT OUTER JOIN sys.server_principals sp2
    ON srm.member_principal_id = sp2.principal_id
    WHERE sp1.type = 'R'
    AND sp2.name = 'NT AUTHORITY\\SYSTEM'"

    sqltest = "SELECT sp1.name
    FROM sys.server_role_members srm
    LEFT JOIN sys.server_principals sp1
    ON srm.role_principal_id = sp1.principal_id
    LEFT OUTER JOIN sys.server_principals sp2
    ON srm.member_principal_id = sp2.principal_id
    WHERE sp1.type = 'R'
    AND sp2.name = 'JEFF-WIN-SQLSVR\\Administrator'"

    Puppet.debug "#{sql}"
    client = nil
    resultset = nil
    #begin
      # works, but the SqlConnection object offers no recordset...
      # config = { admin_login_type: 'WINDOWS_LOGIN', instance_name: 'MSSQLSERVER', database: 'MSSQLSERVER', admin_user: '', admin_pass: '', host: 'localhost' } # lint:ignore:140chars
      # client = PuppetX::Sqlserver::SqlServerConnection.new
      # config = { admin_login_type: 'WINDOWS_LOGIN', database: 'MSSQLSERVER', host: 'localhost' }
      client = SqlServerClient.new
      client.open
      client.query(sql)
      resultset = client.data
      resultset.each do |row|
        Puppet.debug "processing role: #{row.to_s}"
        ddl = ddl1
        ddl << row
        ddl << ddl2
        Puppet.debug "ddl...\n#{ddl}"
        if row != 'public'
          client.execute(ddl)
          Puppet.debug "removed user from role: #{row.to_s}"
        end
      end
      client.close
    #rescue StandardError => e
      #Puppet.debug "Facter: sqlserver_roles_assigned_to_nt_authority_system.rb error occurred: #{e}"
    #ensure
      #client.close
    #end

    # %w[public sysadmin]
    resultset
  end
end
