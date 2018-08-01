# sqlserver_sql_logins.rb
#
# Return users using SQL Server authentication, not Windows authentication.
#
# type_desc
# ---------
# CERTIFICATE_MAPPED_USER
# ASYMMETRIC_KEY_MAPPED_USER
# APPLICATION_ROLE
# DATABASE_ROLE
# EXTERNAL_USER
# SQL_USER
# WINDOWS_USER
# WINDOWS_GROUP
# EXTERNAL_GROUPS
#
# @return   An array of strings representing accounts using SQL Server authentication.
# @example  ["public","dbo","guest"]
#
require 'sqlserver_client'

Facter.add('sqlserver_sql_logins.rb') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT name FROM sys.database_principals WHERE type_desc = 'SQL_USER' AND authentication_type_desc = 'DATABASE';"

    Puppet.debug "sqlserver_sql_logins.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
