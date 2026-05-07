while ($true) {
    Write-Host "Running automation at $(Get-Date)"
    python -m api.app.automation_runner
    Write-Host "Waiting 1 minutes..."
    Start-Sleep -Seconds 60
}