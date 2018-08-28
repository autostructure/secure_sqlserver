# sqlserver_encryption_is_master_key_encrypted_by_server.rb
#
# sys.databases
# STATE Field <tinyint>
# 0 = ONLINE
# 1 = RESTORING
# 2 = RECOVERING : SQL Server 2008 through SQL Server 2017
# 3 = RECOVERY_PENDING : SQL Server 2008 through SQL Server 2017
# 4 = SUSPECT
# 5 = EMERGENCY : SQL Server 2008 through SQL Server 2017
# 6 = OFFLINE : SQL Server 2008 through SQL Server 2017
# 7 = COPYING : Azure SQL Database Active Geo-Replication
# 10 = OFFLINE_SECONDARY : Azure SQL Database Active Geo-Replication
#
# Note: For Always On databases, query the database_state or database_state_desc columns of sys.dm_hadr_database_replica_states.

#
# @return   true/false
#
# Dependencies:
# v79087
#
require 'sqlserver_client'

Facter.add('sqlserver_encryption_is_master_key_encrypted_by_server') do
  confine operatingsystem: :windows
  setcode do

    # Note:
    # The query below assumes that the [sa] account is not used as the owner of application databases,
    # in keeping with other STIG guidance. If this is not the case, modify the query accordingly.
    # I don't want to exclude the [sa] account so I removed the condition:
    # "AND owner_sid <> 1"
    # Also, state = 0 means ONLINE.
    
    sql = "SELECT name FROM [master].sys.databases WHERE is_master_key_encrypted_by_server = 1 AND state = 0"

    Puppet.debug "sqlserver_encryption_is_master_key_encrypted_by_server.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.column(sql)
    resultset = client.data
    client.close unless client.nil? || client.closed?
    resultset

  end
end
