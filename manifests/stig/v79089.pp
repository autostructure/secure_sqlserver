# v79089.pp
#
# The Certificate used for encryption must be backed up, stored offline and off-site.
#
define secure_sqlserver::stig::v79089 (
  Boolean       $enforced = false,
  String[1,16]  $instance = 'MSSQLSERVER',
  String        $database,
) {

  if $enforced {
    notify { "v79089: ${instance}\\${database}: v79089 called.":
      loglevel => notice,
    }
  }

}
