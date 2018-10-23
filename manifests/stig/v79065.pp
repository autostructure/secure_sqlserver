# v79065.pp
#
# This class manages DISA STIG vulnerability: V-79065
# SQL Server must enforce approved authorizations for logical access to
# information and system resources in accordance with applicable access control policies.
#
define secure_sqlserver::stig::v79065 (
  String[1,16]  $instance,
  String        $database,
  Boolean       $enforced = false,
) {}
