# v79139.pp
# SQL Server must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.
#
class secure_sqlserver::stig::v79139 (
  Boolean $enforced = false,
  String  $instance = 'MSSQLSERVER',
) {
  if $enforced {

    ##TODO:
    # Do we have to use AUDIT ACTION GROUPS?
    # Do other groups have the failure events too?
    # Need to implement
    # AUDIT ACTION GROUPS
    # for failed permission attempts
    # See:
    # https://www.ultimatewindowssecurity.com/sqlserver/auditpolicy/auditactiongroups/default.aspx
    # https://www.ultimatewindowssecurity.com/sqlserver/auditpolicy/auditactiongroups/DATABASE_ROLE_MEMBER_CHANGE_GROUP.aspx
    # https://www.ultimatewindowssecurity.com/sqlserver/auditlog/default.aspx

    # SQL Server Audit Action Group:
    # DATABASE_PERMISSION_CHANGE_GROUP
    #
    # Available in:
    # Database Audit Specification
    # Server Audit Specification
    #
    # New to:		2012	2016
    #
    # This group tracks permission changes on a database itself as opposed to permission changes on objects within that database. If you enable this group in a server audit specification, it will track permission changes on all databases within that SQL Server instance. If you enable this group in a database audit specification, it will only check permission changes on that particular database.
    #
    # LOGbinder for SQL Server events generated under this Audit Action Group:
    #
    # EventID	Description
    # 24179	  Grant database permissions succeeded
    # 24180	  Grant database permissions failed *****************************
    # 24181	  Grant database permissions with grant succeeded
    # 24182	  Grant database permissions with grant failed
    # 24183	  Deny database permissions succeeded
    # 24184	  Deny database permissions failed ******************************
    # 24185	  Deny database permissions with cascade succeeded
    # 24186	  Deny database permissions with cascade failed *****************
    # 24187	Revoke database permissions succeeded
    # 24188	Revoke database permissions failed ******************************
    # 24189	Revoke database permissions with grant succeeded
    # 24190	Revoke database permissions with grant failed *******************
    # 24191	Revoke database permissions with cascade succeeded
    # 24192	Revoke database permissions with cascade failed *****************
    #
    # Source:
    # https://www.ultimatewindowssecurity.com/sqlserver/auditpolicy/auditactiongroups/database_permission_change_group.aspx



    # Create a dedicated audit to capture the retrieval of privilege/permission/role membership information.

    $sql = "SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '')
AND audit_action_name IN
(
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SCHEMA_OBJECT_ACCESS_GROUP'
)"

  $sql_create_server_audit_specification = "CREATE SERVER AUDIT SPECIFICATION STIG_UNSUCCESSFUL_PERMISSION_QUERIES_SERVER_SPECIFICATION
     FOR SERVER AUDIT STIG_AUDIT_UNSUCCESSFUL_PERMISSION_QUERIES
     ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP)"

    $sql_ddl = "--
    --Create a dedicated audit to capture unsuccessful retrieval attempts against privilege/permission/role membership information.

    --Set variables needed by setup script:
    DECLARE @auditName varchar(50), @auditPath varchar(260), @auditGuid uniqueidentifier, @auditFileSize varchar(4), @auditFileCount varchar(4)

    --Define the name of the audit:
    SET @auditName = 'STIG_AUDIT_UNSUCCESSFUL_PERMISSION_QUERIES'

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
