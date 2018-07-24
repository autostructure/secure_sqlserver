# sqlserver_v79177_xp_cmdshell_enabled.rb
#
# Access to xp_cmdshell must be disabled, unless specifically required and approved.
#
# @return   Boolean true/false; true = enabled, false = disabled.
#
require 'sqlserver_client'

Facter.add('sqlserver_v79177_xp_cmdshell_enabled') do
  confine operatingsystem: :windows
  setcode do

    # If the value of "config_value" is "0", this is not a finding.
    # (So zero must mean disabled)
    sql = "EXEC SP_CONFIGURE 'show advanced options', '1';
RECONFIGURE WITH OVERRIDE;
EXEC SP_CONFIGURE 'xp_cmdshell';"

    Puppet.debug "sqlserver_v79177_xp_cmndshell_enabled.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
