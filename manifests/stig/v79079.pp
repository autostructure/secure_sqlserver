# v79079.pp
#
# Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers,
# links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.
#
define secure_sqlserver::stig::v79079 (
  String[1,16]  $instance,
  String        $database,
  Boolean       $enforced = false,
) {

  if $enforced {
    notify { "v79079: ${instance}\\${database}: Skipping vulnerability 79079.":
      loglevel => warning,
    }
  }

}
