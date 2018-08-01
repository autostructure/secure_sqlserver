# sqlserver_sql_logins.rb
#
# Return users using SQL LOGIN, not WINDOWS LOGIN.
#
# type_desc
# ---------
# CERTIFICATE_MAPPED_USER
# SERVER_ROLE
# DATABASE_ROLE
# SQL_USER
# WINDOWS_USER
# GROUP
#
# @return   An array of strings representing accounts using SQL Server authentication.
# @example  ['user1','user2']
#
#
require 'sqlserver_client'

Facter.add('sqlserver_sql_logins.rb') do
  confine operatingsystem: :windows
  setcode do

    #sql = "SELECT name FROM sys.database_principals WHERE type_desc = 'SQL_USER' AND authentication_type_desc = 'DATABASE';"
    sql = "SELECT name FROM sys.database_principals"

    Puppet.debug "sqlserver_sql_logins.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
