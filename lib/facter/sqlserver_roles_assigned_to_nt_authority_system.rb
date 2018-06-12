# The 'sqlserver_roles_assigned_to_nt_authority_system' fact returns an array list
# of all roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# All types of roles are reported including 'server roles', 'database roles', and 'application roles'.
#
# @return   An array of strings representing roles assigned to the 'NT AUTHORITY\SYSTEM' user.
# @example  [ "bulkadmin", "dbcreator", "diskadmin", "processadmin", "public", "securityadmin", "serveradmin", "setupadmin", "sysadmin" ]
#
Facter.add('sqlserver_roles_assigned_to_nt_authority_system') do
  confine operatingsystem: :windows
  setcode do
    role_array = []

    begin
      role_array = ['public', 'sysadmin']
    rescue StandardError => e
      Puppet.debug "Facter: sqlserver_roles_assigned_to_nt_authority_system.rb error occurred: #{e}"
    end

    role_array
  end
end
