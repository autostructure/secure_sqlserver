# sqlserver_v79165_file_changes.rb
# Rule: SQL Server must limit privileges to change software modules,
# to include stored procedures, functions and triggers,
# and links to software external to SQL Server.
#
# @return   Array of comma-separated values.
# @example  facter -p
#           sqlserver_v79165_file_changes =>
#           "MD5","C5B78318255BDBED9B74A691E65A341D","C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\testfile.txt"
#           "MD5","68E4B3679171FA49D61E094789A54008","C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\testfile.txt"
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
    result.split("\n")
  end
end
