# This class manages DISA STIG vulnerability: V-79129
# SQL Server must protect against a user falsely repudiating by ensuring the
# NT AUTHORITY/SYSTEM account is not used for administration.
#
# Type Description
# ---- ------------------------
# C    CERTIFICATE_MAPPED_LOGIN
# R    SERVER_ROLE
# S    SQL_LOGIN
# U    WINDOWS_LOGIN
#
class secure_sqlserver::stig::v79129 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  if $enforced {

    # make sure the "NT AUTHORITY\SYSTEM" user only has the public role assigned.
    $system_user = 'NT AUTHORITY\SYSTEM'

    $assigned_roles = $facts['sqlserver_v79129_roles_assigned_to_nt_authority_system']

    unless $assigned_roles == undef or $assigned_roles == '' {
      $assigned_roles.each |$single_role| {
        $sql_dcl = "ALTER SERVER ROLE '${single_role}' DROP MEMBER '${system_user}';"

        ::secure_sqlserver::log { "v79129_sql_dcl = \n${sql_dcl}": }

        sqlserver_tsql{ "drop_nt_authority_system_role_${single_role}":
          instance => $instance,
          command  => $sql_dcl,
          require  => Sqlserver::Config[$instance],
        }
      }
    }
  }
}
