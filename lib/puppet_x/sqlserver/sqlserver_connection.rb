# Extending the PuppetX::Sqlserver::SqlConnection class because it doesnt return a resultset.
#
# @return
# @example
#

require File.expand_path(File.join(File.dirname(__FILE__), '../..', 'puppet/provider/sqlserver'))
require File.expand_path(File.join(File.dirname(__FILE__), '../..', 'puppet_x/sqlserver/sql_connection'))

module PuppetX
  module Sqlserver

    class SqlServerConnection < SqlConnection

    end

  end
end
