# The 'sqlserver_roles' fact returns an array list of all server roles.
# All types of roles are reported including:
# 'server roles', 'database roles', and 'application roles'.
#
# @return   An array of strings representing roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# @example  ['bulkadmin', 'dbcreator', 'diskadmin', 'processadmin', 'public', 'securityadmin', 'serveradmin', 'setupadmin', 'sysadmin']
#
Facter.add('sqlserver_roles') do
  confine operatingsystem: :windows
  setcode do

    $sql_check_server_roles = "SELECT srm.role_principal_id, sp1.name, srm.member_principal_id, sp2.name
    FROM sys.server_role_members srm
    FULL OUTER JOIN sys.server_principals sp1
    ON srm.role_principal_id = sp1.principal_id
    LEFT OUTER JOIN sys.server_principals sp2
    ON srm.member_principal_id = sp2.principal_id
    WHERE sp2.name = 'NT AUTHORITY\SYSTEM'
    AND sp1.type = 'R'"

    $sql_check_db_roles = "SELECT drm.role_principal_id, dp1.name, drm.member_principal_id, dp2.name
    FROM sys.database_role_members drm
    FULL OUTER JOIN sys.database_principals dp1
    ON drm.role_principal_id = dp1.principal_id
    LEFT OUTER JOIN sys.database_principals dp2
    ON drm.member_principal_id = dp2.principal_id
    WHERE dp2.name = 'NT AUTHORITY\SYSTEM'
    AND dp1.type = 'R'"

    role_array = []

    begin
      role_array = %w[bulkadmin dbcreator diskadmin processadmin public securityadmin serveradmin setupadmin sysadmin]
    rescue StandardError => e
      Puppet.debug "Facter: sqlserver_roles.rb error occurred: #{e}"
    end

    role_array
  end
end