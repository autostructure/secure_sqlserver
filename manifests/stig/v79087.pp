# v79087.pp
#
# This class manages DISA STIG vulnerability: V-79087
# The Database Master Key must be encrypted by the Service Master Key,
# where a Database Master Key is required
# and another encryption method has not been specified.
#
define secure_sqlserver::stig::v79087 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    # SELECT name
    # FROM [master].sys.databases
    # WHERE is_master_key_encrypted_by_server = 1
    # AND owner_sid <> 1
    # AND state = 0
    # AND name = $database
    # (Note that this query assumes that the [sa] account is not used as the owner of application databases, in keeping with other STIG guidance. If this is not the case, modify the query accordingly.)

    if $facts['sqlserver_encryption_is_master_key_encrypted_by_server'] {

      # password regex test for at least:
      # a lowercase letter,
      # an uppercase letter,
      # a digit,
      # a special character (i.e. a non-word character) and
      # a length of 8+ characters...
      $regex_password_check = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{8,}$/'
      $password = 'password'
      $filepath = 'C:\v79087.txt'

      #$facts['sqlserver_sql_authenticated_users'].each |String $sql_login| {

      if $password =~ $regex_password_check {
        $sql = "USE ${database}; BACKUP MASTER KEY TO FILE = '${filepath}' ENCRYPTION BY PASSWORD = '${password}';"
        ::secure_sqlserver::log { "${instance}\\${database}: v79087 sql = \n${sql}": }
        sqlserver_tsql{ "v79087_database_master_key_backup_${instance}_${database}_${username}":
          instance => $instance,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      } else {
        ::secure_sqlserver::log { "V-79087: ${instance}\\${database} needs a valid password (pwd failed check).":
          loglevel => debug,
        }
      }

    } else {
      ::secure_sqlserver::log { "V-79087: ${instance}\\${database} is not encrypted.":
        loglevel => debug,
      }
    }

  }
}
