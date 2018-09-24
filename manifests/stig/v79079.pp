# v79079.pp
#
# Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers,
# links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.
#
define secure_sqlserver::stig::v79079 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {
    notify { "v79079: ${instance}\\${database}: v79079 called.":
      loglevel => notice,
    }
  }

}
