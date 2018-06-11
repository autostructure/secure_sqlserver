# This class manages DISA STIG vulnerability: V-79129
#
#
class secure_sqlserver::stig::v79129 (
  Boolean $enforced = false,
) {

    # NT AUTHORITY\SYSTEM
    # Server_Role = Public
    # make sure that is the only role.

    #sqlserver::user::permissions{'INSERT-loggingUser-On-rp_logging':
    #  user        => 'loggingUser',
    #  database    => 'rp_logging',
    #  permissions => 'INSERT',
    #  require     => Sqlserver::User['rp_logging-loggingUser'],
    #}

    #sqlserver_tsql{ 'Always running':
    #  instance => 'MSSQLSERVER',
    #  command  => 'EXEC notified_executor()',
    #}

}
