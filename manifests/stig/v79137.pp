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
    #
    # SELECT name AS 'Audit Name',
    # status_desc AS 'Audit Status',
    # audit_file_path AS 'Current Audit File'
    # FROM sys.dm_server_audit_status

    $auditable_events = $facts['sqlserver_auditable_events']

    # If the auditing the retrieval of privilege/permission/role membership information is required,
    # execute the following query to verify the SCHEMA_OBJECT_ACCESS_GROUP is included in the server audit specification:
    #
    # SELECT a.name AS 'AuditName',
    # s.name AS 'SpecName',
    # d.audit_action_name AS 'ActionName',
    # d.audited_result AS 'Result'
    # FROM sys.server_audit_specifications s
    # JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    # JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    # WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    #
    # If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding.



    # Fix...
    $sql_ddl = "--Create a dedicated audit to capture the retrieval of privilege/permission/role membership information.

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

  --Delete the audit if it currently exists:

  --Disable the Server Audit Specification:
  DECLARE @auditName varchar(50), @disableSpecification nvarchar(max)
  SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
  SET @disableSpecification = '
  IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName + '_SERVER_SPECIFICATION'')
  ALTER SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION] WITH (STATE = OFF);'
  EXEC(@disableSpecification)

  --Drop the Server Audit Specification:
  DECLARE @auditName varchar(50), @dropSpecification nvarchar(max)
  SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
  SET @dropSpecification = '
  IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName + '_SERVER_SPECIFICATION'')
  DROP SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION];'
  EXEC(@dropSpecification)

  --Disable the Server Audit:
  DECLARE @auditName varchar(50), @disableAudit nvarchar(max)
  SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
  SET @disableAudit = '
  IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
  ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = OFF);'
  EXEC(@disableAudit)

  --Drop the Server Audit:
  DECLARE @auditName varchar(50), @dropAudit nvarchar(max)
  SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
  SET @dropAudit = '
  IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
  DROP SERVER AUDIT [' + @auditName + '];'
  EXEC(@dropAudit)

  --
  --Set up the SQL Server Audit:
  --

  --Create the Server Audit:
  DECLARE @auditName varchar(50), @auditPath varchar(260), @auditGuid varchar(40), @auditFileSize varchar(4), @auditFileCount varchar(5)

  SELECT @auditName = Value FROM #SetupVars WHERE Variable = 'auditName'
  SELECT @auditPath = Value FROM #SetupVars WHERE Variable = 'auditPath'
  SELECT @auditGuid = Value FROM #SetupVars WHERE Variable = 'auditGuid'
  SELECT @auditFileSize = Value FROM #SetupVars WHERE Variable = 'auditFileSize'
  SELECT @auditFileCount = Value FROM #SetupVars WHERE Variable = 'auditFileCount'

  DECLARE @createStatement nvarchar(max)
  SET @createStatement = '
  CREATE SERVER AUDIT [' + @auditName + ']
  TO FILE
  (
  FILEPATH = ''' + @auditPath + '''
  , MAXSIZE = ' + @auditFileSize + ' MB
  , MAX_ROLLOVER_FILES = ' + CASE WHEN @auditFileCount = -1 THEN 'UNLIMITED' ELSE @auditFileCount END + '
  , RESERVE_DISK_SPACE = OFF
  )
  WITH
  (
  QUEUE_DELAY = 1000
  , ON_FAILURE = SHUTDOWN
  , AUDIT_GUID = ''' + @auditGuid + '''
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

  --Turn on the Audit:
  DECLARE @auditName varchar(50), @enableAudit nvarchar(max)
  SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
  SET @enableAudit = '
  IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
  ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = ON);'
  EXEC(@enableAudit)

  --Create the server audit specifications:
  DECLARE @auditName varchar(50), @createSpecification nvarchar(max)
  SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
  SET @createSpecification = '
  CREATE SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION]
  FOR SERVER AUDIT [' + @auditName + ']
  ADD (SCHEMA_OBJECT_ACCESS_GROUP)
  WITH (STATE = ON);'
  EXEC(@createSpecification)

  --Clean up:
  DROP TABLE
  "

    sqlserver_tsql{ 'v79137-create-dedicated-audit-capturing-role-changes':
      instance => $instance,
      command  => $sql_ddl,
      require  => Sqlserver::Config[$instance],
    }

    # If SQL Server is required to audit the retrieval of privilege/permission/role membership information,
    # create a dedicated audit to capture this information.
    #
    # Set variables needed by setup script:
    # DECLARE @auditName varchar(50), @auditPath varchar(260), @auditGuid uniqueidentifier, @auditFileSize varchar(4), @auditFileCount varchar(4)
    #
    # Define the name of the audit:
    # SET @auditName = 'STIG_Audit_Permissions_Queries'
    #
    # Define the directory in which audit log files reside:
    # SET @auditPath = 'C:\Program Files\Microsoft SQL Server\MSSQL13.SQL2016\MSSQL\Audits'
    #
    # Define the unique identifier for the audit:
    # SET @auditGuid = NEWID()
    #
    # Define the maximum size for a single audit file (MB):
    # SET @auditFileSize = 200
    #
    # Define the number of files that should be kept online. Use -1 for unlimited:
    # SET @auditFileCount = 50
    #
    # Insert the variables into a temp table so they survive for the duration of the script:
    # CREATE TABLE #SetupVars
    # (
    # Variable varchar(50),
    # Value varchar(260)
    # )
    # INSERT INTO #SetupVars (Variable, Value)
    # VALUES ('auditName', @auditName),
    # ('auditPath', @auditPath),
    # ('auditGuid', convert(varchar(40), @auditGuid)),
    # ('auditFileSize', @auditFileSize),
    # ('auditFileCount', @auditFileCount)
    # GO
    #
    # Delete the audit if it currently exists:
    #
    # Disable the Server Audit Specification:
    # DECLARE @auditName varchar(50), @disableSpecification nvarchar(max)
    # SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
    # SET @disableSpecification = '
    # IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName + '_SERVER_SPECIFICATION'')
    # ALTER SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION] WITH (STATE = OFF);'
    # EXEC(@disableSpecification)
    # GO
    #
    # Drop the Server Audit Specification:
    # DECLARE @auditName varchar(50), @dropSpecification nvarchar(max)
    # SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
    # SET @dropSpecification = '
    # IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName + '_SERVER_SPECIFICATION'')
    # DROP SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION];'
    # EXEC(@dropSpecification)
    # GO
    #
    # Disable the Server Audit:
    # DECLARE @auditName varchar(50), @disableAudit nvarchar(max)
    # SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
    # SET @disableAudit = '
    # IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
    # ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = OFF);'
    # EXEC(@disableAudit)
    # GO
    #
    # Drop the Server Audit:
    # DECLARE @auditName varchar(50), @dropAudit nvarchar(max)
    # SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
    # SET @dropAudit = '
    # IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
    # DROP SERVER AUDIT [' + @auditName + '];'
    # EXEC(@dropAudit)
    # GO
    #
    # Set up the SQL Server Audit:
    #
    # USE [master];
    # GO
    #
    # Create the Server Audit:
    # DECLARE @auditName varchar(50), @auditPath varchar(260), @auditGuid varchar(40), @auditFileSize varchar(4), @auditFileCount varchar(5)
    #
    # SELECT @auditName = Value FROM #SetupVars WHERE Variable = 'auditName'
    # SELECT @auditPath = Value FROM #SetupVars WHERE Variable = 'auditPath'
    # SELECT @auditGuid = Value FROM #SetupVars WHERE Variable = 'auditGuid'
    # SELECT @auditFileSize = Value FROM #SetupVars WHERE Variable = 'auditFileSize'
    # SELECT @auditFileCount = Value FROM #SetupVars WHERE Variable = 'auditFileCount'
    #
    # DECLARE @createStatement nvarchar(max)
    # SET @createStatement = '
    # CREATE SERVER AUDIT [' + @auditName + ']
    # TO FILE
    # (
    # FILEPATH = ''' + @auditPath + '''
    # , MAXSIZE = ' + @auditFileSize + ' MB
    # , MAX_ROLLOVER_FILES = ' + CASE WHEN @auditFileCount = -1 THEN 'UNLIMITED' ELSE @auditFileCount END + '
    # , RESERVE_DISK_SPACE = OFF
    # )
    # WITH
    # (
    # QUEUE_DELAY = 1000
    # , ON_FAILURE = SHUTDOWN
    # , AUDIT_GUID = ''' + @auditGuid + '''
    # )
    # WHERE ([Schema_Name] = ''sys'' AND [Object_Name] = ''all_objects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''database_permissions'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''database_principals'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''database_role_members'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_column_store_object_pool'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_db_xtp_object_stats'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_os_memory_objects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_xe_object_columns'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_xe_objects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''dm_xe_session_object_columns'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''filetable_system_defined_objects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''linked_logins'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''login_token'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''objects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''remote_logins'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_permissions'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_principal_credentials'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_principals'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''server_role_members'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sql_logins'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''syscacheobjects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''syslogins'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysobjects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysoledbusers'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''syspermissions'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysremotelogins'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''system_objects'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''sysusers'')
    # OR ([Schema_Name] = ''sys'' AND [Object_Name] = ''user_token'')
    # '
    #
    # EXEC(@createStatement)
    # GO
    #
    # Turn on the Audit:
    # DECLARE @auditName varchar(50), @enableAudit nvarchar(max)
    # SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
    # SET @enableAudit = '
    # IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
    # ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = ON);'
    # EXEC(@enableAudit)
    # GO
    #
    # Create the server audit specifications:
    # DECLARE @auditName varchar(50), @createSpecification nvarchar(max)
    # SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
    # SET @createSpecification = '
    # CREATE SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION]
    # FOR SERVER AUDIT [' + @auditName + ']
    # ADD (SCHEMA_OBJECT_ACCESS_GROUP)
    # WITH (STATE = ON);'
    # EXEC(@createSpecification)
    # GO
    #
    # Clean up:
    # DROP TABLE
    # #SetupVars
  }
}
