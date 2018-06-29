# v79135.pp
# SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM)
# to select which auditable events are to be audited.
#
# This is a separation of responsibilities.
# Separating the audit administration from other administration (like blanket sysadmin).
#
class secure_sqlserver::stig::v79137 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  if $enforced {
    # Check...

    # Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding.

    $auditable_events = $facts['sqlserver_auditable_events']

    # If the auditing the retrieval of privilege/permission/role membership information is required,
    # execute the following query to verify the SCHEMA_OBJECT_ACCESS_GROUP is included in the server audit specification:
    # If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding.

    $schema_object_access_group = $facts['sqlserver_schema_object_access_group']

    # Fix...
    if $auditable_events == [] and $schema_object_access_group == [] {

      ::secure_sqlserver::log { 'v79137 - creating audit to capture privilege-permission-role changes.': }

      # Create a dedicated audit to capture the retrieval of privilege/permission/role membership information.

      $sql_ddl = "--Create a dedicated audit to capture privilege/permission/role membership information.

      --Set variables needed by setup script:
      DECLARE @auditName varchar(50), @auditPath varchar(260), @auditGuid uniqueidentifier, @auditFileSize varchar(4), @auditFileCount varchar(4)

      --Define the name of the audit:
      SET @auditName = 'STIG_Audit_Permissions_Queries'

      --Define the directory in which audit log files reside:
      SET @auditPath = 'C:\Program Files\Microsoft SQL Server\MSSQL13.SQL2016\MSSQL\Audits'

      --Define the unique identifier for the audit:
      SET @auditGuid = NEWID()

      --Define the maximum size for a single audit file (MB):
      SET @auditFileSize = 200

      --Define the number of files that should be kept online. Use -1 for unlimited:
      SET @auditFileCount = 50

      --Insert the variables into a temp table so they survive for the duration of the script:
      CREATE TABLE #SetupVars
      (
      Variable varchar(50),
      Value varchar(260)
      )
      INSERT INTO #SetupVars (Variable, Value)
      VALUES ('auditName', @auditName),
      ('auditPath', @auditPath),
      ('auditGuid', convert(varchar(40), @auditGuid)),
      ('auditFileSize', @auditFileSize),
      ('auditFileCount', @auditFileCount)

      --Disable the Server Audit Specification:
      DECLARE @auditName2 varchar(50), @disableSpecification nvarchar(max)
      SET @auditName2 = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @disableSpecification = '
      IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName2 + '_SERVER_SPECIFICATION'')
      ALTER SERVER AUDIT SPECIFICATION [' + @auditName2 + '_SERVER_SPECIFICATION] WITH (STATE = OFF);'
      EXEC(@disableSpecification)

      DECLARE @auditName3 varchar(50), @dropSpecification nvarchar(max)
      SET @auditName3 = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @dropSpecification = '
      IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName3 + '_SERVER_SPECIFICATION'')
      DROP SERVER AUDIT SPECIFICATION [' + @auditName3 + '_SERVER_SPECIFICATION];'
      EXEC(@dropSpecification)

      DECLARE @auditName4 varchar(50), @disableAudit nvarchar(max)
      SET @auditName4 = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @disableAudit = '
      IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName4 + ''')
      ALTER SERVER AUDIT [' + @auditName4 + '] WITH (STATE = OFF);'
      EXEC(@disableAudit)

      DECLARE @auditName5 varchar(50), @dropAudit nvarchar(max)
      SET @auditName5 = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @dropAudit = '
      IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName5 + ''')
      DROP SERVER AUDIT [' + @auditName5 + '];'
      EXEC(@dropAudit)

      DECLARE @auditName6 varchar(50), @auditPath2 varchar(260), @auditGuid2 varchar(40), @auditFileSize2 varchar(4), @auditFileCount2 varchar(5)

      SELECT @auditName6 = Value FROM #SetupVars WHERE Variable = 'auditName'
      SELECT @auditPath2 = Value FROM #SetupVars WHERE Variable = 'auditPath'
      SELECT @auditGuid2 = Value FROM #SetupVars WHERE Variable = 'auditGuid'
      SELECT @auditFileSize2 = Value FROM #SetupVars WHERE Variable = 'auditFileSize'
      SELECT @auditFileCount2 = Value FROM #SetupVars WHERE Variable = 'auditFileCount'

      DECLARE @createStatement nvarchar(max)
      SET @createStatement = '
      CREATE SERVER AUDIT [' + @auditName6 + ']
      TO FILE
      (
      FILEPATH = ''' + @auditPath2 + '''
      , MAXSIZE = ' + @auditFileSize2 + ' MB
      , MAX_ROLLOVER_FILES = ' + CASE WHEN @auditFileCount2 = -1 THEN 'UNLIMITED' ELSE @auditFileCount2 END + '
      , RESERVE_DISK_SPACE = OFF
      )
      WITH
      (
      QUEUE_DELAY = 1000
      , ON_FAILURE = SHUTDOWN
      , AUDIT_GUID = ''' + @auditGuid2 + '''
      )
      WHERE ([Schema_Name] = ''sys'' AND [Object_Name] = ''all_objects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''database_permissions'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''database_principals'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''database_role_members'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_column_store_object_pool'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_db_xtp_object_stats'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_os_memory_objects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_xe_object_columns'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_xe_objects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_xe_session_object_columns'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''filetable_system_defined_objects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''linked_logins'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''login_token'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''objects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''remote_logins'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_permissions'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_principal_credentials'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_principals'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_role_members'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sql_logins'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''syscacheobjects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''syslogins'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysobjects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysoledbusers'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''syspermissions'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysremotelogins'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''system_objects'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysusers'')
      OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''user_token'')
      '
      EXEC(@createStatement)

      DECLARE @auditName7 varchar(50), @enableAudit nvarchar(max)
      SET @auditName7 = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @enableAudit = '
      IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName7 + ''')
      ALTER SERVER AUDIT [' + @auditName7 + '] WITH (STATE = ON);'
      EXEC(@enableAudit)

      DECLARE @auditName8 varchar(50), @createSpecification nvarchar(max)
      SET @auditName8 = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @createSpecification = '
      CREATE SERVER AUDIT SPECIFICATION [' + @auditName8 + '_SERVER_SPECIFICATION]
      FOR SERVER AUDIT [' + @auditName8 + ']
      ADD (SCHEMA_OBJECT_ACCESS_GROUP)
      WITH (STATE = ON);'
      EXEC(@createSpecification)

      --Clean up:
      DROP TABLE #SetupVars"

      sqlserver_tsql{ 'v79137-sql_ddl':
        instance => $instance,
        command  => $sql_ddl,
        require  => Sqlserver::Config[$instance],
      }
    }
  }
}
