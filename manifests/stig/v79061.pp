# This class manages DISA STIG vulnerability: V-79061
# SQL Server databases must integrate with an organization-level authentication/access mechanism
# providing account management and automation for all users, groups, roles, and any other principals.
#
# Similar to v79121
#
# *** REBOOT REQ'D ***
#
define secure_sqlserver::stig::v79061 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {

    # A contained databases contains both dats & metadata.
    # Instead of storing metadata in the system databases, it is all contained within the database
    # and not stored in master.
    # Fail hardening if it is a contained database...
    if $facts['sqlserver_enabled_contained_databases'] {
      ::secure_sqlserver::log { "***WARNING*** Contained databases is enabled on ${instance}\\${database}. This is a finding per vulnerability V-79061.":
        loglevel => warning,
      }
      fail("***FAIL*** Contained databases is enabled on ${instance}\\${database}. This is a finding per vulnerability V-79061.  Stopping module execution.")
    }

    if $facts['sqlserver_authentication_mode'] != 'Windows Authentication' and downcase($database) == 'master' {
      # Use Windows Authentication...
      # set login mode to Windows authentication (not SQL Server authentication)
      # this requires a restart to take effect.
      # NOTE:
      # The puppetlabs-registry module has trouble with duplicate resources
      # even though I have a unique title below. So, as a fix, I am only
      # checking the registry once, by only checking when the master database calls this class.
      registry::value { "v79061_${instance}_${database}":
        key   => 'HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer',
        value => 'LoginMode',
        type  => 'dword',
        data  => '0x00000002',
      }
      # reboot
    }

    # yaml file contains approved_users, skip the DROP for any in the list.
    $approved_users = lookup('secure_sqlserver::approved_sql_login_users')

    $facts['sqlserver_sql_authenticated_users'].each |String $sql_login| {
      unless $sql_login in $approved_users {
        $sql = "USE ${database}; DROP USER '${sql_login}';"

        ::secure_sqlserver::log { "${instance}\\${database}: v79061 sql = \n${sql}": }

        sqlserver_tsql { "v79061_drop_user_${instance}_${database}_${username}":
          instance => $instance,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      }
    }

  }

}
