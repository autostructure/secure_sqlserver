# v79085.pp
#
# This class manages DISA STIG vulnerability: V-79085
# The Database Master Key encryption password must meet DOD password complexity requirements.
#
define secure_sqlserver::stig::v79085 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {
  if $enforced {

    unless empty($facts['sqlserver_encryption_is_master_key_encrypted_by_server'][${database}]) {

      # password regex test for at least:
      # a lowercase letter,
      # an uppercase letter,
      # a digit,
      # a special character (i.e. a non-word character) and
      # a length of 15+ characters...
      $regex_password_check = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{15,}$/'
      $password = lookup('secure_sqlserver::database_master_key_encryption_password')

      #$facts['sqlserver_sql_authenticated_users'].each |String $sql_login| {

      if $password =~ $regex_password_check or empty($password) {
        $sql = "USE ${database}; ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = '${password}';"
        ::secure_sqlserver::log { "V-79085: ${instance}\\${database}: sql = \n${sql}": }
        sqlserver_tsql{ "v79085_database_master_key_password_${instance}_${database}":
          instance => $instance,
          command  => $sql,
          require  => Sqlserver::Config[$instance],
        }
      } else {
        ::secure_sqlserver::log { "V-79085: ${instance}\\${database} needs a valid password (pwd failed check).":
          loglevel => warning,
        }
      }

    } else {
      ::secure_sqlserver::log { "V-79085: ${instance}\\${database} is not encrypted.":
        loglevel => debug,
      }
    }

  }
}
