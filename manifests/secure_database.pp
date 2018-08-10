# This class calls all classes that secure a MS SQL Server 2016 database.
#
define secure_sqlserver::secure_database (
  String[1,16]  $instance = 'MSSQLSERVER',
  String[1,128] $database,
) {

  $prefix = "${instance}::${database}"

  # Database STIGs...
  # Using a define types over classes, since we invoke it more than once...

  notify { "${prefix}_secure_database_output" :
    message  => "instance=${instance}",
    loglevel => warning,
  }

  ::secure_sqlserver::stig::v79061 { "${prefix}-v79061":
    enforced => lookup('::secure_sqlserver::stig::v79061::enforced'),
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79065 { "${prefix}-v79065":
    enforced => lookup('::secure_sqlserver::stig::v79065::enforced'),
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79067 { "${prefix}-v79067":
    enforced => lookup('::secure_sqlserver::stig::v79067::enforced'),
    instance => $instance,
    database => $database,
  }
  ::secure_sqlserver::stig::v79071 { "${prefix}-v79071":
    enforced => lookup('::secure_sqlserver::stig::v79071::enforced'),
    instance => $instance,
    database => $database,
  }

}
