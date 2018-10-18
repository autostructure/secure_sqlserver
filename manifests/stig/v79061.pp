# This class manages DISA STIG vulnerability: V-79061
# SQL Server databases must integrate with an organization-level authentication/access mechanism
# providing account management and automation for all users, groups, roles, and any other principals.
#
# NOTE: The sa login can only connect to the server by using SQL Server Authentication.
#
# NOTE: Similar to v79121
#
# NOTE:
# Consider skipping reboot here.
# Because,
# 1) the tsql may make it seem like you need a reboot every agent run.
# 2) the instance level stigs use a registry module to apply the change too (reboot @ that level)
#
# *** REBOOT REQ'D ***
#
define secure_sqlserver::stig::v79061 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
  Array         $approved_sql_login_users,
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
      # The sa login can only connect to the server by using SQL Server Authentication.
      # NOTE:
      # The puppetlabs-registry module has trouble with duplicate resources
      # even though I have a unique title below. So, as a fix, I am only
      # checking the registry once, by only checking when the master database calls this class.
      # NOTE:
      # The puppetlabs-registry module is difficult to work with, trying MS SQL Server's stored procedure for registry settings.

      # ::secure_sqlserver::log { "***v79061*** ${instance}\\${database}":
      #   loglevel => warning,
      # }

      $sql = "EXECUTE master..xp_instance_regwrite 'HKEY_LOCAL_MACHINE','Software\Microsoft\MSSQLServer\MSSQLServer\','LoginMode','REG_DWORD', 2"

      ::secure_sqlserver::log { "${instance}\\${database}: v79061 sql = \n${sql}": }

      sqlserver_tsql { "v79061_regwrite_${instance}_${database}":
        instance => $instance,
        database => $database,
        command  => $sql,
        require  => Sqlserver::Config[$instance],
      }

      # if !defined(Registry_key['HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer']) {
      #     registry_key { 'HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer': }
      # }

      # registry::value { "v79061_${instance}_${database}":
      #   key   => 'HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer',
      #   value => 'LoginMode',
      #   type  => 'dword',
      #   data  => '0x00000002',
      # }

      # registry_value { 'HKEY_LOCAL_MACHINE\Software\Microsoft\MSSQLServer\MSSQLServer\LoginMode':
      #   ensure => present,
      #   type  => 'dword',
      #   data  => '0x00000002',
      # }

      # reboot
    }

    # skip the DROP for any user approved for sql_loginapproved_sql_login_users.
    $facts['sqlserver_sql_authenticated_users'].each |String $sql_login| {
      unless $sql_login in $approved_sql_login_users {
        $sql = "USE ${database}; DROP USER '${sql_login}';"

        ::secure_sqlserver::log { "${instance}\\${database}: v79061 sql = \n${sql}": }

        sqlserver_tsql { "v79061_drop_user_${instance}_${database}_${username}":
          instance => $instance,
          database => $database,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      }
    }

  }

}
