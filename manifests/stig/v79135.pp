# v79135.pp
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM)
# to select which auditable events are to be audited.
#
# This is a separation of responsibilities.
# Separating the audit administration from other administration (like blanket sysadmin).
#
class secure_sqlserver::stig::v79135 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {

  $new_audit_role = 'SERVER_AUDIT_MAINTAINERS'
  # STEP 1:
  # Retrieve findings...

  $audit_permission_findings = $facts['sqlserver_v79135_audit_permission_findings']

  # STEP 2:

  # Create a server role specifically for audit maintainers and give it permission to
  # maintain audits without granting it unnecessary permissions...

  $sql_create_role = "CREATE SERVER ROLE \"${new_audit_role}\"; GRANT ALTER ANY SERVER AUDIT TO \"${new_audit_role}\";"

  ::secure_sqlserver::log { "v79135_sql_create_role = \n${sql_create_role}": }

  sqlserver_tsql{ 'v79135_create_server_audit_role':
    instance => $instance,
    command  => $sql_create_role,
  }

  # STEP 3:

  # Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements
  # to remove the ALTER ANY SERVER AUDIT permission from all logins.
  # Then, for each authorized login, run the statement:
  # ALTER SERVER ROLE SERVER_AUDIT_MAINTAINERS ADD MEMBER;
  # GO

  $audit_permission_findings.each |$finding| {

    notify {"v79135 audit_permission_finding (role loop)...\n${finding}":}

    $class = $finding['Securable Class']
    $user = $finding['Securable']
    $role = $finding['Role Name']

    # no role represents a revoke-permission-related record.
    # nil or empty facts are not undef, but an empty string ('').
    # a not-empty role field = drop this user from this role.

    if $class == 'SERVER_PRINCIPAL' {
      # DROP MEMBER
      unless $role == undef or $role == '' {
        if $user in ('NT SERVICE\SQLWriter', 'NT SERVICE\MSSQLSERVER', 'sa') {
          ::secure_sqlserver::log {"v79135: Skipping user: ${user}, do not have permissions to drop from role: ${role}.":
            loglevel => 'warning',
          }
        } else {
          $sql_dcl_drop_member = "ALTER SERVER ROLE \"${role}\" DROP MEMBER \"${user}\";"
          ::secure_sqlserver::log { "v79135_sql_dcl=${sql_dcl_drop_member}": }
          sqlserver_tsql{ "v79135_alter_${role}_drop_member_${user}":
            instance => $instance,
            command  => $sql_dcl_drop_member,
          }
        }
      }
      # ADD MEMBER
      $sql_dcl_add_member = "ALTER SERVER ROLE \"${new_audit_role}\" ADD MEMBER \"${user}\";"
      ::secure_sqlserver::log { "v79135_sql_dcl=${sql_dcl_add_member}": }
      sqlserver_tsql{ "v79135_alter_${new_audit_role}_add_member_${user}":
        instance => $instance,
        command  => $sql_dcl_add_member,
      }
    }
  }

  # STEP 4:

  # Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ...
  # statements to remove CONTROL SERVER, ALTER ANY DATABASE and CREATE ANY DATABASE
  # permissions from logins that do not need them.

  $audit_permission_findings.each |$finding| {

    notify {"v79135 audit_permission_finding (permission loop)...\n${finding}":}

    $class = $finding['Securable Class']
    $permission = $finding['Permission']
    $role = $finding['Role Name']
    $user = $finding['Securable']

    if $role == undef or $role == '' {

      unless $permission == undef or $permission == '' {
        # a not-empty role field = drop this user from this role.
        $sql_dcl_revoke_permission = "REVOKE ${permission} FROM \"${user}\";"
        ::secure_sqlserver::log { "v79135_sql_dcl=${sql_dcl_revoke_permission}": }
        sqlserver_tsql{ "v79135_revoke_${permission}_from_${user}":
          instance => $instance,
          command  => $sql_dcl_revoke_permission,
        }
      }
      # 'CONTROL SERVER', 'ALTER ANY DATABASE', 'CREATE ANY DATABASE': {
      #   # no role represents a revoke-permission-related record.
      #   notify {"v79135 (1 of 3) permissions = ${permission} [${class}, ${user}]":}
      # }

    }
  }
}
