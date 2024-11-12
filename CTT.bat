@echo off
color 0F
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    mshta "about:<html><head><style>body{font-family: Arial, sans-serif; font-size:12pt; text-align:center; padding:10px; margin:0;} p{font-size: 10pt; color:red;} button{padding:5px 15px; font-size:10pt;}</style><script>window.resizeTo(300,150);</script></head><body><p>Requires Administrator privileges.</p><button onclick='window.close()'>Close</button></body></html>"
    exit /b
)
echo Creating System Restore Point...
powershell -Command "Checkpoint-Computer -Description 'RestorePointFromScript' -RestorePointType 'MODIFY_SETTINGS'" >nul 2>&1
if %errorlevel% neq 0 (
    mshta "javascript:alert('Warning: Restore Point was not created. Click Ok to proceed.');close();"
)

:MainMenu
cls
echo ################################
echo #    Astros Version of CTT     #
echo ################################
echo # 1. Run Astros Version of CTT #
echo ################################    
set /p input="Choose an option : "

if /i %input% == 1 goto Warning



:Warning
cls
powershell -Command "Write-Host '----READ----' -ForegroundColor Red -BackgroundColor Black"
powershell -Command "Write-Host 'Screen May Flicker/Go black dont worry its explorer reseting' -ForegroundColor White -BackgroundColor Red"
powershell -Command "Write-Host 'This Can Take A While' -ForegroundColor White -BackgroundColor Red"
powershell -Command "Write-Host 'Dont Close Till Success PopUp' -ForegroundColor White -BackgroundColor Red" 
powershell -Command "Write-Host 'Disables Gamedvr/Xbox' -ForegroundColor White -BackgroundColor Red"
powershell -Command "Write-Host 'Disables Printing' -ForegroundColor White -BackgroundColor Red" 
powershell -Command "Write-Host 'Disables Notifications' -ForegroundColor White -BackgroundColor Red"
powershell -Command "Write-Host 'Do You Want To Continue?' -ForegroundColor White -BackgroundColor Red"

powershell -Command "Write-Host '1. Yes' -ForegroundColor White -BackgroundColor Black"
powershell -Command "Write-Host '2. No' -ForegroundColor White -BackgroundColor Black"
set /p input="Choose an option (1-2): "

if /i %input% == 1 goto CTT
if /i %input% == 2 goto 

:CTT
cls
::Disable Activity History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f

::Disable Location
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f

::Disable Notifications
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.LowDisk" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Print.Notification" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.WiFiNetworkManager" /v "Enabled" /t REG_DWORD /d "0" /f

::Disable Storage Sense
powershell -Command "Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Recurse -ErrorAction SilentlyContinue"

::Disable Sticky Keys
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f

::Win 10 right click
powershell -Command "New-Item -Path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Name 'InprocServer32' -Force -Value ''" 

::Show File Extensions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

::Disable Taskbar Widgets
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f

::Set Display For Performance
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DExplorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
powershell -Command "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"

::Disable GameDVR
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f

::Enable Hardware Accelerated GPU Scheduling
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f

::Enable Game Mode
reg add "HKCU\Software\Microsoft\GameBar" /v "GameMode" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 1 /f

::Disable Mouse Acceleration
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f

::Disable Hibernation
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
powercfg.exe /hibernate off

::Disable HomeGroup
sc config HomeGroupListener start=demand 
sc config HomeGroupProvider start=demand

::Disable Unnecessary WiFi Settings
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "Value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "Value" /t REG_DWORD /d 0 /f

::Disable Teredo
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 1 /f

::Disable IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 255 /f
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6"

::Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0

::Set Services to manual
sc config "ALG" start= demand
sc config "AppMgmt" start= demand
sc config "AppReadiness" start= demand
sc config "AppVClient" start= disabled
sc config "Appinfo" start= demand
sc config "AssignedAccessManagerSvc" start= disabled
sc config "AudioEndpointBuilder" start= auto
sc config "AudioSrv" start= auto
sc config "Audiosrv" start= auto
sc config "AxInstSV" start= demand
sc config "BITS" start= delayed-auto
sc config "BrokerInfrastructure" start= auto
sc config "Browser" start= demand
sc config "COMSysApp" start= demand
sc config "CaptureService_*" start= demand
sc config "ClipSVC" start= demand
sc config "ConsentUxUserSvc_*" start= demand
sc config "CoreMessagingRegistrar" start= auto
sc config "CredentialEnrollmentManagerUserSvc_*" start= demand
sc config "CryptSvc" start= auto
sc config "CscService" start= demand
sc config "DPS" start= auto
sc config "DcomLaunch" start= auto
sc config "DcpSvc" start= demand
sc config "DeviceAssociationBrokerSvc_*" start= demand
sc config "DeviceInstall" start= demand
sc config "DevicePickerUserSvc_*" start= demand
sc config "Dhcp" start= auto
sc config "DialogBlockingService" start= disabled
sc config "DispBrokerDesktopSvc" start= auto
sc config "DmEnrollmentSvc" start= demand
sc config "DsmSvc" start= demand
sc config "DusmSvc" start= auto
sc config "EapHost" start= demand
sc config "EntAppSvc" start= demand
sc config "EventLog" start= auto
sc config "EventSystem" start= auto
sc config "Fax" start= demand
sc config "FontCache" start= auto
sc config "FrameServerMonitor" start= demand
sc config "HomeGroupListener" start= demand
sc config "HomeGroupProvider" start= demand
sc config "IEEtwCollectorService" start= demand
sc config "InstallService" start= demand
sc config "InventorySvc" start= demand
sc config "IpxlatCfgSvc" start= demand
sc config "KeyIso" start= auto
sc config "KtmRm" start= demand
sc config "LSM" start= auto
sc config "LanmanWorkstation" start= auto
sc config "LxpSvc" start= demand
sc config "MSDTC" start= demand
sc config "MSiSCSI" start= demand
sc config "MapsBroker" start= delayed-auto
sc config "McpManagementService" start= demand
sc config "MessagingService_*" start= demand
sc config "MicrosoftEdgeElevationService" start= demand
sc config "MixedRealityOpenXRSvc" start= demand
sc config "MsKeyboardFilter" start= demand
sc config "NPSMSvc_*" start= demand
sc config "NaturalAuthentication" start= demand
sc config "NcaSvc" start= demand
sc config "NcdAutoSetup" start= demand
sc config "NetSetupSvc" start= demand
sc config "NetTcpPortSharing" start= disabled
sc config "Netman" start= demand
sc config "NlaSvc" start= demand
sc config "P9RdrService_*" start= demand
sc config "PNRPAutoReg" start= demand
sc config "PNRPsvc" start= demand
sc config "PeerDistSvc" start= demand
sc config "PenService_*" start= demand
sc config "PerfHost" start= demand
sc config "PlugPlay" start= demand
sc config "PolicyAgent" start= demand
sc config "Power" start= auto
sc config "PrintWorkflowUserSvc_*" start= demand
sc config "ProfSvc" start= auto
sc config "PushToInstall" start= demand
sc config "QWAVE" start= demand
sc config "RasAuto" start= demand
sc config "RasMan" start= demand
sc config "RemoteAccess" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "RetailDemo" start= demand
sc config "RmSvc" start= demand
sc config "RpcEptMapper" start= auto
sc config "RpcLocator" start= demand
sc config "RpcSs" start= auto
sc config "SCPolicySvc" start= demand
sc config "SDRSVC" start= demand
sc config "SENS" start= auto
sc config "SNMPTRAP" start= demand
sc config "SNMPTrap" start= demand
sc config "SSDPSRV" start= demand
sc config "SamSs" start= auto
sc config "ScDeviceEnum" start= demand
sc config "Sense" start= demand
sc config "SessionEnv" start= demand
sc config "SharedRealitySvc" start= demand
sc config "ShellHWDetection" start= auto
sc config "SmsRouter" start= demand
sc config "SstpSvc" start= demand
sc config "SysMain" start= auto
sc config "TapiSrv" start= demand
sc config "TermService" start= auto
sc config "TextInputManagementService" start= demand
sc config "Themes" start= auto
sc config "TieringEngineService" start= demand
sc config "TimeBroker" start= demand
sc config "TokenBroker" start= demand
sc config "TrkWks" start= auto
sc config "TroubleshootingSvc" start= demand
sc config "TrustedInstaller" start= demand
sc config "UI0Detect" start= demand
sc config "UdkUserSvc_*" start= demand
sc config "UevAgentService" start= disabled
sc config "UmRdpService" start= demand
sc config "UserManager" start= auto
sc config "VGAuthService" start= auto
sc config "VMTools" start= auto
sc config "VSS" start= demand
sc config "VacSvc" start= demand
sc config "VaultSvc" start= auto
sc config "WEPHOSTSVC" start= demand
sc config "WFDSConMgrSvc" start= demand
sc config "WMPNetworkSvc" start= demand
sc config "WManSvc" start= demand
sc config "WSService" start= demand
sc config "WSearch" start= delayed-auto
sc config "WalletService" start= demand
sc config "WarpJITSvc" start= demand
sc config "WcsPlugInService" start= demand
sc config "WdiServiceHost" start= demand
sc config "WdiSystemHost" start= demand
sc config "Wecsvc" start= demand
sc config "WiaRpc" start= demand
sc config "WinRM" start= demand
sc config "Winmgmt" start= auto
sc config "WlanSvc" start= auto
sc config "WpcMonSvc" start= demand
sc config "XblAuthManager" start= demand
sc config "XboxNetApiSvc" start= demand
sc config "camsvc" start= demand
sc config "cloudidsvc" start= demand
sc config "dcsvc" start= demand
sc config "defragsvc" start= demand
sc config "diagnosticshub.standardcollector.service" start= demand
sc config "dot3svc" start= demand
sc config "edgeupdate" start= demand
sc config "edgeupdatem" start= demand
sc config "embeddedmode" start= demand
sc config "fdPHost" start= demand
sc config "hidserv" start= demand
sc config "iphlpsvc" start= auto
sc config "lltdsvc" start= demand
sc config "netprofm" start= demand
sc config "nsi" start= auto
sc config "p2pimsvc" start= demand
sc config "p2psvc" start= demand
sc config "perceptionsimulation" start= demand
sc config "pla" start= demand
sc config "seclogon" start= demand
sc config "shpamsvc" start= disabled
sc config "smphost" start= demand
sc config "spectrum" start= demand
sc config "sppsvc" start= delayed-auto
sc config "ssh-agent" start= disabled
sc config "svsvc" start= demand
sc config "swprv" start= demand
sc config "tiledatamodelsvc" start= auto
sc config "tzautoupdate" start= disabled
sc config "uhssvc" start= disabled
sc config "upnphost" start= demand
sc config "vds" start= demand
sc config "vm3dservice" start= demand
sc config "vmvss" start= demand
sc config "wbengine" start= demand
sc config "wcncsvc" start= demand
sc config "webthreatdefsvc" start= demand
sc config "webthreatdefusersvc_*" start= auto
sc config "wercplsupport" start= demand
sc config "wlpasvc" start= demand
sc config "wmiApSrv" start= demand
sc config "workfolderssvc" start= demand
sc config "wudfsvc" start= demand
sc config "BthHFSrv" start= auto

::Telementry
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable 
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable 
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable  
schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable  
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

::Disable Printer Services and Tasks
sc config PrintNotify start= disabled
sc config Spooler start= disabled
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable 
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable 

::Uninstall/Disable OneDrive
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /q /s 
rd "%USERPROFILE%\OneDrive" /q /s
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /q /s 
rd "%PROGRAMDATA%\Microsoft OneDrive" /q /s 
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"
winget uninstall --silent --accept-source-agreements Microsoft.OneDrive >nul 2>&1
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f 
reg unload "hku\Default"
del /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" 
schtasks /delete /tn "OneDrive*" /f 
start explorer.exe
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f

::Mircosoft App Remover
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Cortana* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.BingSports* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.BingFinance* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Windows.Phone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.CommsPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Appconnector* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.MinecraftUWP* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Wallet* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.GroupMe10* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *king.com.CandyCrushSaga* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *ShazamEntertainmentLtd.Shazam* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *9E2F88E3.Twitter* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *ClearChannelRadioDigital.iHeartRadio* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *D5EA27B7.Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *PandoraMediaInc.29680B314EFC2* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *46928bounde.EclipseManager* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *ActiproSoftwareLLC.562882FEEB491* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *SpotifyAB.SpotifyMusic* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Advertising.Xaml* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.RemoteDesktop* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Todos* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Windows.Search* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Windows.Cortana* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *windowsterminal* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.PowerAutomateDesktop* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.Office.Outlook* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.WindowsNotepad* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.OneDrive* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.ParentalControls* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Clipchamp* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.RemoteDesktop* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *Microsoft.RemoteDesktop_10.2.1810.0_x64__8wekyb3d8bbwe* | Remove-AppxPackage" 
taskkill /F /IM Teams.exe 
taskkill /F /IM msteams.exe 
taskkill /F /IM msteams_autostarter.exe 
taskkill /F /IM msteamsupdate.exe 
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *MicrosoftTeams* | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *MicrosoftTeams_24102.2309.2851.4917_x64__8wekyb3d8bbwe* | Remove-AppxPackage"

::Clean
del "%LocalAppData%\Microsoft\Windows\INetCache\." /s /f /q
del "%AppData%\Local\Microsoft\Windows\INetCookies\." /s /f /q
del "%temp%" /s /f /q
del "%AppData%\Discord\Cache\." /s /f /q 
del "%AppData%\Discord\Code Cache\." /s /f /q 
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
del "C:\Windows\System32\SleepStudy" /s /f /q
rmdir /S /Q "%AppData%\Local\Microsoft\Windows\INetCache\"
rmdir /S /Q "%AppData%\Local\Microsoft\Windows\INetCookies"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\WebCache"
rmdir /S /Q "%AppData%\Local\Temp\"
rd "%AppData%\Discord\Cache" /s /q 
rd "%AppData%\Discord\Code Cache" /s /q 
rd "%SystemDrive%\$GetCurrent" /s /q
rd "%SystemDrive%\$SysReset" /s /q
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q
rd "%SystemDrive%\$WinREAgent" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
rd /s /q %LocalAppData%\Temp
rd /s /q %LocalAppData%\Temp\mozilla-temp-files
rmdir /s /q "%SystemRoot%\System32\SleepStudy"
rmdir /s /q "%SystemRoot%\System32\SleepStudy 
Del /S /F /Q %temp%
Del /S /F /Q %Windir%\Temp
Del /S /F /Q C:\WINDOWS\Prefetch
goto success

:success
mshta "javascript:alert('Success.');close();"