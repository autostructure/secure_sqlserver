# v79171.pp
# Default demonstration and sample databases, database objects, and applications must be removed.
#
# Remove demonstration databases:
# 1. pubs
# 2. Northwinds
# 3. AdventureWorks
# 4. WorldwideImporters
#
class secure_sqlserver::stig::v79171 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  if $enforced {

    $sql = "DROP DATABASE IF EXISTS pubs, Northwinds, AdventureWorks, WorldwideImporters"

    sqlserver_tsql{ 'v79171-drop-demo-databases':
      instance => $instance,
      command  => $sql,
      require  => Sqlserver::Config[$instance],
    }

  }
}
