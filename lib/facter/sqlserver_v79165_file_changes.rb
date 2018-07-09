# sqlserver_v79165_file_changes.rb
#
# @return
# @example
#
# Get-FileHash -Path "c:\Windows\Temp\* -Algorithm MD5 | ConvertTo-Json | Out-File "c:\puppet.secure-sqlserver.filehashes.json"
# Get-FileHash -Path "c:\Windows\Temp\* -Algorithm MD5 | ConvertTo-Json | Out-File "c:\puppet.secure-sqlserver.temp.json"
# Compare-Object $(Get-Content "c:\puppet.secure-sqlserver.filehashes.json") $(Get-Content "c:\puppet.secure-sqlserver.temp.json")
#
Facter.add('sqlserver_v79165_file_changes') do
  confine operatingsystem: :windows
  setcode do
    root = 'c:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\*'
    cmd1 = "if (-NOT (Test-Path 'c:\\puppet.secure-sqlserver.filehash-baseline.csv')) { Get-FileHash -Path '#{root}' -Algorithm MD5 | ConvertTo-Csv | Out-File 'c:\\puppet.secure-sqlserver.filehash-baseline.csv' }"# lint:ignore:140chars
    cmd2 = "Get-FileHash -Path '#{root}' -Algorithm MD5 | ConvertTo-Csv | Out-File 'c:\\puppet.secure-sqlserver.filehash-tempfile.csv'"# lint:ignore:140chars
    cmd3 = "Compare-Object $(Get-Content 'c:\\puppet.secure-sqlserver.filehash-baseline.csv') $(Get-Content 'c:\\puppet.secure-sqlserver.filehash-tempfile.csv') | Select InputObject | Format-Table -Wrap -HideTableHeaders"# lint:ignore:140chars
    cmd4 = "del 'c:\\puppet.secure-sqlserver.filehash-tempfile.json'"
    Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd1}\"")
    Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd2}\"")
    result = Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd3}\"")
    Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd4}\"")
    result
  end
end
