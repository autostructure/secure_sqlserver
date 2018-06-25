# sqlserver_whoami_sid.rb
# Some registry resources require a SID.
#
# @return   The SID of the current user.
# @example  S-1-5-21-804-36083-3409395816-4202414035-500
#
require 'sqlserver_client'

Facter.add('sqlserver_whoami_sid') do
  confine operatingsystem: :windows
  setcode do

    cmd = "whoami /user /nh"
    line = Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd}\"")
    sid = line[/\S+$/]
    sid

  end
end
