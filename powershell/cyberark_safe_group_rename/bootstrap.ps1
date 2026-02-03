# bootstrap.ps1
$modules = @(
  @{ Name = 'ImportExcel'; MinVersion = '7.8.6' }
)

foreach ($m in $modules) {
  $installed = Get-Module -ListAvailable $m.Name | Sort-Object Version -Descending | Select-Object -First 1
  if (-not $installed -or $installed.Version -lt [version]$m.MinVersion) {
    Install-Module $m.Name -Scope CurrentUser -Force
  }
  Import-Module $m.Name -ErrorAction Stop
}
