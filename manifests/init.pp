#
# This module secures Microsoft SQL Server 2016
# @Usage
# class { '::secure_sqlserver': }
#
class secure_sqlserver
{

  class { '::secure_sqlserver::controller': }

}
