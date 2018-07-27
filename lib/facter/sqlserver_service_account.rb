# sqlserver_service_account.rb
#
require 'hiera'
include 'lib/hiera.rb'

Facter.add('sqlserver_service_account') do
  confine operatingsystem: :windows
  setcode do

    #Hiera.lookup('profile::windows_sqlserver::svc_acct')
    Hiera.lookup('secure_sqlserver::stig::v79119::enforced')
    
  end
end
