# This fact returns an array list of all roles assigned to the 'NT AUTHORITY\SYSTEM' user.
#
# @returns
#   Example:
#   [ "dbcreator",
#     "public",
#     "sysadmin",
#   ]
#
Facter.add('nt_authority_system_assigned_roles') do
  confine operatingsystem: :windows
  setcode do
    role_array = []

    begin
      role_array = ['dbcreator', 'sysadmin']
    rescue StandardError => e
      Puppet.debug "Facter: nt_authority_system_assigned_roles.rb error occurred: #{e}"
    end

    role_array
  end
end
