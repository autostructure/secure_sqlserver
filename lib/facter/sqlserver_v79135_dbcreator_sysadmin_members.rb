# sqlserver_v79135_dbcreator_sysadmin_members.rb
# Review the server roles and individual logins that have the following role memberships,
# all of which enable the ability to create and maintain audit definitions:
# sysadmin
# dbcreator
#
# @return   An array of hashes representing role and user name data.
# @example  [{
#             login => 'NT Service\MSSQLSERVER',
#             role => 'sysadmin',
#             type => 'U',
#             type_description => 'WINDOWS_LOGIN'
#           }]
#
require 'sqlserver_client'

Facter.add('sqlserver_v79135_dbcreator_sysadmin_members') do
  confine operatingsystem: :windows
  setcode do

    sql = "SELECT sp2.name as login
                , sp1.name as role
                , sp2.type as type
                , sp2.type_desc as type_description
             FROM sys.server_role_members srm
            LEFT JOIN sys.server_principals sp1
                   ON srm.role_principal_id = sp1.principal_id
      LEFT OUTER JOIN sys.server_principals sp2
                   ON srm.member_principal_id = sp2.principal_id
                WHERE sp1.name in ('dbcreator','sysadmin')"

    Puppet.debug "sqlserver_v79135_dbcreator_sysadmin_members.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.query(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset
  end
end
