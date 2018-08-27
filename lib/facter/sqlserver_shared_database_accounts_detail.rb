# sqlserver_shared_database_accounts_detail.rb
# Same as 'sqlserver_shared_accounts', except more detail is added by calling
# a powershell command.
#
# Type Description
# ---- ------------------------
# C    CERTIFICATE_MAPPED_LOGIN
# R    DATABASE_ROLE
# S    SQL_LOGIN
# U    WINDOWS_LOGIN
# G    GROUP
#
# @return
# @example
#
# Dependencies:
# v79067
#
require 'sqlserver_client'

Facter.add('sqlserver_shared_database_accounts_detail') do
  confine operatingsystem: :windows
  setcode do

    retval = []

    sql = "SELECT name FROM sys.database_principals WHERE type in ('U','G') AND name LIKE '%$'"

    Puppet.debug "sqlserver_shared_database_accounts_detail.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?

    resultset.each do |domain_user|

      # username should NOT have a dollar sign at the end per STIG (you omit the $)...
      username = domain_user.match(/(?<=(?:\\|\/)).*$/)[1]
      cmd = "([ADSISearcher]\"(&(!ObjectCategory=Computer)(Name=#{username}))\").FindAll()"

      begin
        line = Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd}\"")
        retval.push(username)
      rescue StandardError => e
        # Skip if there is no Active Directory, it will error.
      end

    end

    retval

  end
end
