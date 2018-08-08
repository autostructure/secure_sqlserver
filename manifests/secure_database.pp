# This class calls all classes that secure a MS SQL Server 2016 database.
#
define secure_sqlserver::secure_database (
  String[1,16]  $instance = 'MSSQLSERVER',
  String[1,128] $database,
) {

  $prefix = "${instance}::${database}"

  # Database STIGs...
  # using a define type over class, since we make multiple calls...

  # $enforced = hiera_lookup(::secure_sqlserver::stig::v79061::enforced)

  ::secure_sqlserver::stig::v79061 { "${prefix}-v79061":
    enforced => true,
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79065 { "${prefix}-v79065":
    enforced => true,
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79065 { "${prefix}-v79067":
    enforced => true,
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79071 { "${prefix}-v79071":
    enforced => true,
    instance => $instance,
    database => $database,
  }

}
