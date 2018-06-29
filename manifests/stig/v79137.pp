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

      $sql_ddl1_create_temp_table = "--Create a dedicated audit to capture privilege/permission/role membership information.

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

      GO"

      sqlserver_tsql{ 'v79137-sql_ddl1_create_temp_table':
        instance => $instance,
        command  => $sql_ddl1_create_temp_table,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl2_disable_audit_spec = "--Delete the audit if it currently exists:

      --Disable the Server Audit Specification:
      DECLARE @auditName varchar(50), @disableSpecification nvarchar(max)
      SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @disableSpecification = '
      IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName + '_SERVER_SPECIFICATION'')
      ALTER SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION] WITH (STATE = OFF);'
      EXEC(@disableSpecification)"

      sqlserver_tsql{ 'v79137-sql_ddl2_disable_audit_spec':
        instance => $instance,
        command  => $sql_ddl2_disable_audit_spec,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl3_drop_server_audit_spec = "--Drop the Server Audit Specification:
      DECLARE @auditName varchar(50), @dropSpecification nvarchar(max)
      SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @dropSpecification = '
      IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N''' + @auditName + '_SERVER_SPECIFICATION'')
      DROP SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION];'
      EXEC(@dropSpecification)"

      sqlserver_tsql{ 'v79137-sql_ddl3_drop_server_audit_spec':
        instance => $instance,
        command  => $sql_ddl3_drop_server_audit_spec,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl4_disable_server_audit = "--Disable the Server Audit:
      DECLARE @auditName varchar(50), @disableAudit nvarchar(max)
      SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @disableAudit = '
      IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
      ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = OFF);'
      EXEC(@disableAudit)"

      sqlserver_tsql{ 'v79137-sql_ddl4_disable_server_audit':
        instance => $instance,
        command  => $sql_ddl4_disable_server_audit,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl5_drop_server_audit = "--Drop the Server Audit:
      DECLARE @auditName varchar(50), @dropAudit nvarchar(max)
      SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @dropAudit = '
      IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
      DROP SERVER AUDIT [' + @auditName + '];'
      EXEC(@dropAudit)"

      sqlserver_tsql{ 'v79137-sql_ddl5_drop_server_audit':
        instance => $instance,
        command  => $sql_ddl5_drop_server_audit,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl6_create_server_audit = "--Set up the SQL Server Audit:
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
      EXEC(@createStatement)"

      sqlserver_tsql{ 'v79137-sql_ddl6_create_server_audit':
        instance => $instance,
        command  => $sql_ddl6_create_server_audit,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl7_turn_audit_on = "
      --Turn on the Audit:
      DECLARE @auditName varchar(50), @enableAudit nvarchar(max)
      SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @enableAudit = '
      IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N''' + @auditName + ''')
      ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = ON);'
      EXEC(@enableAudit)"

      sqlserver_tsql{ 'v79137-sql_ddl7_turn_audit_on':
        instance => $instance,
        command  => $sql_ddl7_turn_audit_on,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl8_create_server_audit_spec = "
      --Create the server audit specifications:
      DECLARE @auditName varchar(50), @createSpecification nvarchar(max)
      SET @auditName = (SELECT Value FROM #SetupVars WHERE Variable = 'auditName')
      SET @createSpecification = '
      CREATE SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION]
      FOR SERVER AUDIT [' + @auditName + ']
      ADD (SCHEMA_OBJECT_ACCESS_GROUP)
      WITH (STATE = ON);'
      EXEC(@createSpecification)"

      sqlserver_tsql{ 'v79137-sql_ddl8_create_server_audit_spec':
        instance => $instance,
        command  => $sql_ddl8_create_server_audit_spec,
        require  => Sqlserver::Config[$instance],
      }

      $sql_ddl9_clean_up = "
      --Clean up:
      DROP TABLE #SetupVars
      "

      sqlserver_tsql{ 'v79137-sql_ddl9_clean_up':
        instance => $instance,
        command  => $sql_ddl9_clean_up,
        require  => Sqlserver::Config[$instance],
      }
    }
  }
}
