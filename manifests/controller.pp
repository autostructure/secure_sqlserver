# This class manages other sqlserver classes.
#
# Usage:
# class { '::secure_sqlserver':
#   sa_acct => '<username>',
# }
#
class secure_sqlserver::controller {

  # NOTE: using 'Down-Level Logon Name' format for usernames.
  $netbios_user = $facts['identity']['user']
  $fqdn_user = $facts['id']
  $sa_acct = lookup('secure_sqlserver::sa_acct')
  $port = empty(lookup('secure_sqlserver::port')) ? {
    false   => lookup('secure_sqlserver::port'),
    default => 1433,
  }

  $instances = $facts['sqlserver_instances']['SQL_2016'].keys

  if empty($instances) {
    fail('secure_sqlserver failure: No instances of SQL Server 2016 were discovered in the sqlserver_instances puppet fact (part of the puppetlabs-sqlserver module).')
  }

  $single_instance = $instances[0]

  notify { 'secure_sqlserver:_controller_msg1':
    message  => "secure_sqlserver::controller: Running in SINGLE_INSTANCE mode: instance=${single_instance}",
    loglevel => info,
  }

  # need sqlserver_config for sqlserver_tsql commands, set auth to windows authentication (no passwords required)
  sqlserver::config { $single_instance:
    admin_login_type => 'WINDOWS_LOGIN',
  }

  class { '::secure_sqlserver::secure_instance':
    instance => $single_instance,
  }

  # Next, cycle through all the databases and secure them...

  $databases = $facts['sqlserver_databases']

  if empty($databases) {
    # fail('secure_sqlserver failure: No SQL Server 2016 databases were discovered.')
    ::secure_sqlserver::log { 'No SQL Server 2016 databases were discovered.':
      loglevel => alert,
    }
  }

  $databases.each |String $database| {

    ::secure_sqlserver::log { "Securing the '${database}' database...":
      loglevel => info,
    }

    # using a define type over class, since we make multiple calls...
    ::secure_sqlserver::secure_database { "secure_database_${database}":
      instance => $single_instance,
      database => $database,
    }

  }

}
