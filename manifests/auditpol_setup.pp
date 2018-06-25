# This class sets up secpol for event auditing to the Windows Security Log.
# See:
# https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/write-sql-server-audit-events-to-the-security-log?view=sql-server-2017
#
class secure_sqlserver::auditpol_setup (
  String[1,16] $instance = 'MSSQLSERVER',
) {

  ##TODO:
  # 1. Ask if audit setup is necessary.
  # 2. Find a powershell command to simulate secpol.msc interface


  $puppet_agent_sid = $facts['sqlserver_whoami_sid']
  $sqlserver_service_user_sid = ''

  # Provide full permission for the SQL Server service account to the registry hive
  # HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security

  #reg_acl { 'hklm:SYSTEM\CurrentControlSet\Services\EventLog\Security':
  #  inherit_from_parent => false,
  #  owner               => $user_sid,
  #  permissions         => [
  #  {
  #    'RegistryRights'    => 'FullControl',
  #    'AccessControlType' => 'Allow',
  #    'IdentityReference' => $sqlserver_service_user_sid,
  #    'IsInherited'       => false,
  #    'InheritanceFlags'  => 'None',
  #    'PropagationFlags'  => 'None',
  #  }],
  #}

  # The account that the SQL Server service is running under must have the
  # generate security audits permission
  # to write to the Windows Security log.
  # By default, the LOCAL SERVICE and the NETWORK SERVICE accounts have this permission.
  #  This step is not required if SQL Server is running under one of those accounts.

  $cmd = "auditpol /set /subcategory:'application generated' /success:enable /failure:enable"
  #exec { 'auditpol_call':
  #  command => $cmd,
  #  path    => 'c:\windows\system32',
  #}

  ##TODO:
  # Find PS command to simulate secpol.msc interface
  #
  # To grant the generate security audits permission to an account using secpol
  # For any Windows operating system, on the Start menu, click Run.
  # Type secpol.msc and then click OK. If the User Access Control dialog box appears, click Continue.
  # In the Local Security Policy tool, expand Security Settings, expand Local Policies, and then click User Rights Assignment.
  # In the results pane, double-click Generate security audits.
  # On the Local Security Setting tab, click Add User or Group.
  # In the Select Users, Computers, or Groups dialog box, either type the name of the user account, such as domain1\user1 and then click OK, or click Advanced and search for the account.
  # Click OK.
  # Close the Security Policy tool.
  # Restart SQL Server to enable this setting.

}
