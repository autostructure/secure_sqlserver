# The 'sqlserver_databases' fact returns an array list of all databases found in an instance.
# The databases are discovered by querying the 'sys.sysdatabases' table.
#
# @return   An array of strings representing a list of all an instance's databases.
# @example  ['master', 'tempdb', 'model', 'msdb']
#
Facter.add('sqlserver_databases') do
  confine operatingsystem: :windows
  setcode do

    databases = []

    # system databases
    #select name fom sys.sysdatabases where dbid <5
    # user databases
    #select name fom sys.sysdatabases where dbid >4
    sql = 'select name from sys.sysdatabases'

    Puppet.debug "sqlserver_databases.rb sql...\n#{sql}"

    client = SqlServerClient.new
    client.open
    client.hasharray(sql)
    # An ADO Recordset's GetRows method returns an array
    # of columns, so we'll use the transpose method to
    # convert it to an array of rows
    databases = client.data
    client.close unless client.nil? || client.closed?

    #databases = %w[master tempdb model msdb]

    databases
  end
end
