# secure_instance.pp
#
# This class calls all vulnerability mitigating classes that secure a
# Microsoft SQL Server 2016 instance (an install).
#
class secure_sqlserver::secure_instance (
  String       $sa_acct,
  String[1,16] $instance = 'MSSQLSERVER',
  String       $port     = 1433,
) {
  # Instance-level Vulnerabilities (installation level)...

  class { '::secure_sqlserver::stig::v79119':
    instance => $instance,
  }

  class { '::secure_sqlserver::stig::v79121': }

  class { '::secure_sqlserver::stig::v79123':
    port => $port,
    user => $sa_acct,
  }

  class { '::secure_sqlserver::stig::v79129':
    instance => $instance,
  }

  class { '::secure_sqlserver::stig::v79131':
    instance => $instance,
  }

  class { '::secure_sqlserver::stig::v79133':
    instance => $instance,
  }

  class { '::secure_sqlserver::stig::v79135':
    instance => $instance,
  }

  class { '::secure_sqlserver::stig::v79137':
    instance => $instance,
  }
}
