# v79171.pp
# Default demonstration and sample databases, database objects, and applications must be removed.
#
# Remove demonstration databases:
# 1. pubs
# 2. Northwinds
# 3. AdventureWorks
# 4. WorldwideImporters
#
# Dropping a database deletes the database from an instance of SQL Server and
# deletes the physical disk files used by the database.
# If the database or any one of its files is offline when it is dropped,
# the disk files are not deleted. These files can be deleted manually by using Windows Explorer.
# To remove a database from the current server without deleting the files from the file system,
# use sp_detach_db.
#
# Warning:
# Dropping a database that has FILE_SNAPSHOT backups associated with it will succeed,
# but the database files that have associated snapshots will not be deleted to avoid
# invalidating the backups referring to these database files.
#
# The file will be truncated, but will not be physically deleted in order to keep the FILE_SNAPSHOT backups intact.
# For more information, see SQL Server Backup and Restore with Microsoft Azure Blob Storage Service.
# Applies to: SQL Server 2016 (13.x) through current version.
# Source:
# https://docs.microsoft.com/en-us/sql/t-sql/statements/drop-database-transact-sql?view=sql-server-2017

class secure_sqlserver::stig::v79171 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  if $enforced {


  }
}
