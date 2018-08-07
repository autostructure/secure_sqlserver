# This class calls all classes that secure a MS SQL Server 2016 database.
#
define secure_sqlserver::secure_database (
  String[1,16]  $instance = 'MSSQLSERVER',
  String[1,128] $database,
) {

  $class1 = "${instance}::${database}::secure_sqlserver::stig::v79061"
  $class2 = "${instance}::${database}::secure_sqlserver::stig::v79071"

  ::secure_sqlserver::log { "secure_database...\n${class1}\n${class2}": }

  # Database STIGs...
  class { $class1 :
    instance => $instance,
    database => $database,
  }

  class { $class2 :
    instance => $instance,
    database => $database,
  }

}
