# v79131.pp
# SQL Server must protect against a user falsely repudiating by ensuring only
# clearly unique Active Directory user accounts can connect to the instance.
#
# Design and implementation also must ensure that applications pass
# individual user identification to the DBMS, even where the application connects
# to the DBMS with a standard, shared account.
#
# If the computer account of a remote computer is granted access to SQL Server,
# any service or scheduled task running as NT AUTHORITY\SYSTEM or NT AUTHORITY\NETWORK SERVICE
# can log into the instance and perform actions. These actions cannot be
# traced back to a specific user or process.
#
# Type Description
# ---- ------------------------
# C    CERTIFICATE_MAPPED_LOGIN
# R    SERVER_ROLE
# S    SQL_LOGIN
# U    WINDOWS_LOGIN
# G    GROUP
#
class secure_sqlserver::stig::v79131 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  $shared_accounts = $facts['sqlserver_v79131_shared_accounts']

  $shared_accounts.each |$drop_user| {

    $sql_dcl = "DROP USER '${drop_user}';"

    ::secure_sqlserver::log { "v79131_sql_dcl=${sql_dcl}": }

    sqlserver_tsql{ "remove_shared_account_${drop_user}":
      instance => $instance,
      command  => $sql_dcl,
    }

  }

}