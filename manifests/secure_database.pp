# This class calls all classes that secure a MS SQL Server 2016 database.
#
define secure_sqlserver::secure_database (
  String[1,16]  $instance = 'MSSQLSERVER',
  String[1,128] $database,
) {

  # Database STIGs...
  class { '::secure_sqlserver::stig::v79061':
    instance => $instance,
    database => $database,
  }

  class { '::secure_sqlserver::stig::v79071':
    instance => $instance,
    database => $database,
  }

}
