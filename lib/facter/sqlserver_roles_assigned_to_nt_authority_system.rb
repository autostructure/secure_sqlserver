# The 'sqlserver_roles_assigned_to_nt_authority_system' fact returns an array list
# of all roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# All types of roles are reported including 'server roles', 'database roles', and 'application roles'.
#
# @return   An array of strings representing roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# @example  ['bulkadmin', 'dbcreator', 'diskadmin', 'processadmin', 'public', 'securityadmin', 'serveradmin', 'setupadmin', 'sysadmin']
#
require 'tiny_tds'
require '../../sqlserver'
require '../../puppet_x/sqlserver/sql_connection'

Facter.add('sqlserver_roles_assigned_to_nt_authority_system') do
  confine operatingsystem: :windows
  setcode do

    role_array = []

    sql = "SELECT sp1.name
    FROM sys.server_role_members srm
    LEFT JOIN sys.server_principals sp1
    ON srm.role_principal_id = sp1.principal_id
    LEFT OUTER JOIN sys.server_principals sp2
    ON srm.member_principal_id = sp2.principal_id
    WHERE sp1.type = 'R'
    AND sp2.name = 'JEFF-WIN-SQLSVR\\Administrator'"

    # AND sp2.name = 'NT AUTHORITY\SYSTEM'"

    Puppet.debug "#{sql}"

    begin

      config = [admin_login_type: 'WINDOWS_LOGIN', instance_name: 'MSSQLSERVER', database: 'MSSQLSERVER', admin_user: '', admin_pass: '', host: 'localhost', database: 'MSSQLSERVER']# lint:ignore:140chars
      connect = PuppetX::Sqlserver::SqlConnection.new
      results = connect.open_and_run_command(sql, config)

      # When FreeTDS sees the "\" character, it automatically chooses a domain login.
      #connect = TinyTds::Client.new username: 'JEFF-WIN-SQLSVR\Administrator',
      #                              host:     'localhost',
      #                              database: 'MSSQLSERVER'

      #results = connect.execute(sql)

      results.each do |row|
        Puppet.debug "#{row}"
        role_array << row
      end
    rescue StandardError => e
      Puppet.debug "Facter: sqlserver_roles_assigned_to_nt_authority_system.rb error occurred: #{e}"
    end

    begin
      #role_array = %w[public sysadmin]
    rescue StandardError => e
      Puppet.debug "Facter: sqlserver_roles_assigned_to_nt_authority_system.rb error occurred: #{e}"
    end

    role_array
  end
end
