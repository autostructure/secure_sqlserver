# This class calls all classes that secure a MS SQL Server 2016 instance.
#
class secure_sqlserver::secure_instance
{
  # instance STIGs...
  class { '::secure_sqlserver::stig::v79119': }
  class { '::secure_sqlserver::stig::v79121': }
  class { '::secure_sqlserver::stig::v79123': }
  class { '::secure_sqlserver::stig::v79129': }
}
