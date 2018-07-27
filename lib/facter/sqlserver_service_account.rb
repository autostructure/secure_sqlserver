# sqlserver_service_account.rb
#
require 'hiera'

Facter.add('sqlserver_service_account') do
  confine operatingsystem: :windows
  setcode do

    Hiera.lookup('profile::windows_sqlserver::svc_acct','Service account not found.')

  end
end
