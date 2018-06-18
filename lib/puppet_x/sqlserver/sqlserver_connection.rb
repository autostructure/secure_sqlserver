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

      class ResultSet

        attr_reader :exitstatus, :error_message

        def getResults()
          Puppet.debug connnection.methods
          return 'test'
        end

        def initialize(has_errors, error_message, connection)
          @exitstatus = has_errors ? 1 : 0

          @error_message = extract_messages(connection) || error_message
        end

        def extract_messages(connection)
          return nil if connection.nil? || connection.Errors.count == 0

          error_count = connection.Errors.count - 1

          ((0..error_count).map { |i| connection.Errors(i).Description.to_s}).join("\n")
        end

        def has_errors
          @exitstatus != 0
        end
      end

    end

  end
end
