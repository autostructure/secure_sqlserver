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
    cmd1 = "if (-NOT (Test-Path \"c:\\puppet.secure-sqlserver.filehash-baseline.json\")) { Get-FileHash -Path \"c:\\Windows\\Temp\\*\" -Algorithm MD5 | ConvertTo-Json | Out-File \"c:\\puppet.secure-sqlserver.filehash-baseline.json\" }"# lint:ignore:140chars
    cmd2 = "Get-FileHash -Path \"c:\\Windows\\Temp\\*\" -Algorithm MD5 | ConvertTo-Json | Out-File \"c:\\puppet.secure-sqlserver.filehash-tempfile.json\""# lint:ignore:140chars
    cmd3 = "Compare-Object $(Get-Content \"c:\\puppet.secure-sqlserver.filehash-baseline.json\") $(Get-Content \"c:\\puppet.secure-sqlserver.filehash-tempfile.json\")"# lint:ignore:140chars
    Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd1}\"")
    Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd2}\"")
    result = Facter::Core::Execution.exec("powershell.exe -Command \"#{cmd3}\"")
    result
  end
end
