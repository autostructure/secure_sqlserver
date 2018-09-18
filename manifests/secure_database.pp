# This class calls all classes that secure a MS SQL Server 2016 database.
#
define secure_sqlserver::secure_database (
  String[1,16]  $instance = 'MSSQLSERVER',
  String[1,128] $database,
) {

  $prefix = "${instance}\\${database}"

  # Database STIGs...
  # Using a define types over classes, since we invoke it more than once...

  notify { "${prefix}_secure_database_output" :
    message  => "instance\\database=${prefix}",
    loglevel => info,
  }

  ::secure_sqlserver::stig::v79061 { "${prefix}-v79061":
    enforced => lookup('secure_sqlserver::stig::v79061::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79065 { "${prefix}-v79065":
    enforced => lookup('secure_sqlserver::stig::v79065::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79067 { "${prefix}-v79067":
    enforced => lookup('secure_sqlserver::stig::v79067::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79071 { "${prefix}-v79071":
    enforced => lookup('secure_sqlserver::stig::v79071::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79073 { "${prefix}-v79073":
    enforced => lookup('secure_sqlserver::stig::v79073::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79075 { "${prefix}-v79075":
    enforced => lookup('secure_sqlserver::stig::v79075::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79077 { "${prefix}-v79077":
    enforced => lookup('secure_sqlserver::stig::v79077::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79081 { "${prefix}-v79081":
    enforced => lookup('secure_sqlserver::stig::v79081::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79085 { "${prefix}-v79085":
    enforced => lookup('secure_sqlserver::stig::v79085::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79087 { "${prefix}-v79087":
    enforced => lookup('secure_sqlserver::stig::v79087::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79111 { "${prefix}-v79111":
    enforced => lookup('secure_sqlserver::stig::v79111::enforced'),
    instance => $instance,
    database => $database,
  }

  ::secure_sqlserver::stig::v79113 { "${prefix}-v79113":
    enforced => lookup('secure_sqlserver::stig::v79113::enforced'),
    instance => $instance,
    database => $database,
  }

}
