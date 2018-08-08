# This class calls all classes that secure a MS SQL Server 2016 database.
#
define secure_sqlserver::secure_database (
  String[1,16]  $instance = 'MSSQLSERVER',
  String[1,128] $database,
) {

  $prefix = "${instance}::${database}"

  # Database STIGs...
  # using a define type over class, since we make multiple calls...

  ::secure_sqlserver::stig::v79061 { "${prefix}-v79061":
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79065 { "${prefix}-v79065":
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79071 { "${prefix}-v79071":
    instance => $instance,
    database => $database,
  }

}
