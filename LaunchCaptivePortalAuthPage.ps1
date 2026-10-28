#Requires -Version 5.1

Param(
    [Switch]$StaHost
)

$ErrorActionPreference = "Stop"

If ([String]::IsNullOrWhiteSpace($PSCommandPath)) {
    Write-Error "[ERROR] Run this script from a file path."
    Exit 1
}

$IsDesktopHost = $PSVersionTable.PSEdition -Eq "Desktop"
$IsStaThread = [System.Threading.Thread]::CurrentThread.ApartmentState -Eq [System.Threading.ApartmentState]::STA
If (($IsDesktopHost -Eq $False) -Or ($IsStaThread -Eq $False)) {
    If ($StaHost -Eq $True) {
        Write-Error "[ERROR] WPF requires Windows PowerShell 5.1 running in STA mode."
        Exit 1
    }

    Write-Host "[INFO] Restarting in Windows PowerShell STA so WPF can open the window."
    $WindowsPowerShell = Join-Path $Env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $ArgumentList = @(
        "-NoProfile",
        "-STA",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $PSCommandPath,
        "-StaHost"
    )
    Start-Process -FilePath $WindowsPowerShell -ArgumentList $ArgumentList -WindowStyle Hidden | Out-Null
    Exit 0
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$WifiMonitorSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public sealed class WifiSnapshot
{
    public WifiSnapshot(string state, string detail)
    {
        State = state;
        Detail = detail;
    }

    public string State { get; private set; }
    public string Detail { get; private set; }
}

public static class WifiMonitor
{
    private const int ErrorSuccess = 0;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorAccessDenied = 5;
    private const uint ClientVersion = 2;
    private const int RadioStateOff = 2;
    private const int SsidLengthOffset = 520;
    private const int ProfileNameOffset = 8;
    private const int InterfaceStateOffset = 528;
    private const int InterfaceStride = 532;

    public static WifiSnapshot Query()
    {
        try
        {
            return QueryCore();
        }
        catch (Exception)
        {
            return new WifiSnapshot("Unavailable", "Could not read Wi-Fi status.");
        }
    }

    private static WifiSnapshot QueryCore()
    {
        uint negotiatedVersion;
        IntPtr handle;
        int openResult = NativeMethods.WlanOpenHandle(ClientVersion, IntPtr.Zero, out negotiatedVersion, out handle);
        if (openResult != ErrorSuccess)
        {
            return new WifiSnapshot("Unavailable", DescribeApiError(openResult));
        }

        try
        {
            IntPtr listPointer;
            int enumResult = NativeMethods.WlanEnumInterfaces(handle, IntPtr.Zero, out listPointer);
            if (enumResult != ErrorSuccess)
            {
                return new WifiSnapshot("Unavailable", DescribeApiError(enumResult));
            }

            if (listPointer == IntPtr.Zero)
            {
                return new WifiSnapshot("NoAdapter", "A wireless adapter was not found.");
            }

            try
            {
                int count = Marshal.ReadInt32(listPointer);
                if (count <= 0)
                {
                    return new WifiSnapshot("NoAdapter", "A wireless adapter was not found.");
                }

                List<string> connectedNames = new List<string>();
                bool anyRadioOn = false;
                bool anyRadioOff = false;
                bool radioStateKnown = false;

                for (int index = 0; index < count; index++)
                {
                    IntPtr item = IntPtr.Add(listPointer, 8 + (index * InterfaceStride));
                    Guid interfaceGuid = (Guid)Marshal.PtrToStructure(item, typeof(Guid));
                    int state = Marshal.ReadInt32(item, InterfaceStateOffset);

                    if (state == 1)
                    {
                        connectedNames.Add(QueryConnectedName(handle, interfaceGuid));
                        continue;
                    }

                    bool radioOff;
                    if (TryQueryRadioOff(handle, interfaceGuid, out radioOff))
                    {
                        radioStateKnown = true;
                        if (radioOff)
                        {
                            anyRadioOff = true;
                        }
                        else
                        {
                            anyRadioOn = true;
                        }
                    }
                }

                if (connectedNames.Count > 0)
                {
                    return new WifiSnapshot("Connected", JoinNetworkNames(connectedNames));
                }

                if (radioStateKnown && anyRadioOff && !anyRadioOn)
                {
                    return new WifiSnapshot("RadioOff", "The Wi-Fi radio is turned off.");
                }

                return new WifiSnapshot("Disconnected", "No Wi-Fi network is associated.");
            }
            finally
            {
                NativeMethods.WlanFreeMemory(listPointer);
            }
        }
        finally
        {
            NativeMethods.WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private static string JoinNetworkNames(List<string> connectedNames)
    {
        List<string> visible = new List<string>();
        bool sawHiddenName = false;
        foreach (string name in connectedNames)
        {
            if (name == null)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                sawHiddenName = true;
                continue;
            }

            visible.Add(name);
        }

        if (visible.Count > 0)
        {
            return "Network: " + string.Join(", ", visible.ToArray());
        }

        if (sawHiddenName)
        {
            return "Connected. The network name is hidden.";
        }

        return "Connected. The network name could not be read.";
    }

    private static string QueryConnectedName(IntPtr handle, Guid interfaceGuid)
    {
        Guid guid = interfaceGuid;
        uint dataSize;
        IntPtr data;
        int result = NativeMethods.WlanQueryInterface(
            handle,
            ref guid,
            7,
            IntPtr.Zero,
            out dataSize,
            out data,
            IntPtr.Zero);

        if (result != ErrorSuccess || data == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            string ssid = ReadSsid(data, dataSize);
            if (!string.IsNullOrWhiteSpace(ssid))
            {
                return ssid;
            }

            return ReadProfileName(data, dataSize);
        }
        finally
        {
            NativeMethods.WlanFreeMemory(data);
        }
    }

    private static bool TryQueryRadioOff(IntPtr handle, Guid interfaceGuid, out bool radioOff)
    {
        radioOff = false;
        Guid guid = interfaceGuid;
        uint dataSize;
        IntPtr data;
        int result = NativeMethods.WlanQueryInterface(
            handle,
            ref guid,
            4,
            IntPtr.Zero,
            out dataSize,
            out data,
            IntPtr.Zero);

        if (result != ErrorSuccess || data == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            if (dataSize < 16)
            {
                return false;
            }

            int phyCount = Marshal.ReadInt32(data);
            if (phyCount <= 0)
            {
                return false;
            }

            if (phyCount > 64)
            {
                phyCount = 64;
            }

            bool sawPhy = false;
            bool anyOff = false;
            for (int index = 0; index < phyCount; index++)
            {
                int phyOffset = 4 + (index * 12);
                if (dataSize < (uint)(phyOffset + 12))
                {
                    break;
                }

                int software = Marshal.ReadInt32(data, phyOffset + 4);
                int hardware = Marshal.ReadInt32(data, phyOffset + 8);
                sawPhy = true;
                if (software == RadioStateOff || hardware == RadioStateOff)
                {
                    anyOff = true;
                }
            }

            if (!sawPhy)
            {
                return false;
            }

            radioOff = anyOff;
            return true;
        }
        finally
        {
            NativeMethods.WlanFreeMemory(data);
        }
    }

    private static string ReadSsid(IntPtr data, uint dataSize)
    {
        if (dataSize < SsidLengthOffset + 4)
        {
            return "";
        }

        int length = Marshal.ReadInt32(data, SsidLengthOffset);
        if (length <= 0)
        {
            return "";
        }

        if (length > 32)
        {
            length = 32;
        }

        if (dataSize < SsidLengthOffset + 4 + length)
        {
            return "";
        }

        byte[] bytes = new byte[length];
        Marshal.Copy(IntPtr.Add(data, SsidLengthOffset + 4), bytes, 0, length);
        return Encoding.UTF8.GetString(bytes).Trim('\0', ' ');
    }

    private static string ReadProfileName(IntPtr data, uint dataSize)
    {
        if (dataSize < ProfileNameOffset + 2)
        {
            return "";
        }

        string name = Marshal.PtrToStringUni(IntPtr.Add(data, ProfileNameOffset), 256) ?? "";
        int terminator = name.IndexOf('\0');
        if (terminator >= 0)
        {
            name = name.Substring(0, terminator);
        }

        return name.Trim();
    }

    private static string DescribeApiError(int errorCode)
    {
        if (errorCode == ErrorServiceNotActive)
        {
            return "The WLAN AutoConfig service is not running.";
        }

        if (errorCode == ErrorAccessDenied)
        {
            return "Access was denied while reading Wi-Fi status.";
        }

        return "Could not read Wi-Fi status (error " + errorCode + ").";
    }

    private static class NativeMethods
    {
        [DllImport("wlanapi.dll")]
        internal static extern int WlanOpenHandle(
            uint clientVersion,
            IntPtr reserved,
            out uint negotiatedVersion,
            out IntPtr clientHandle);

        [DllImport("wlanapi.dll")]
        internal static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

        [DllImport("wlanapi.dll")]
        internal static extern int WlanEnumInterfaces(
            IntPtr clientHandle,
            IntPtr reserved,
            out IntPtr interfaceList);

        [DllImport("wlanapi.dll")]
        internal static extern int WlanQueryInterface(
            IntPtr clientHandle,
            ref Guid interfaceGuid,
            int opCode,
            IntPtr reserved,
            out uint dataSize,
            out IntPtr data,
            IntPtr opcodeValueType);

        [DllImport("wlanapi.dll")]
        internal static extern void WlanFreeMemory(IntPtr memory);
    }
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"WifiMonitor").Type) {
    Add-Type -TypeDefinition $WifiMonitorSource -Language CSharp
}

$CiscoBrowserSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class CiscoBrowserCloser
{
    private static List<IntPtr> FoundHandles = new List<IntPtr>();
    private static List<int> ProcessIds = new List<int>();
    private static EnumWindowsProc WindowCallback = OnWindow;

    public static int RequestClose()
    {
        List<IntPtr> handles = ListVisibleWindows();
        int requested = 0;
        for (int index = 0; index < handles.Count; index++)
        {
            if (PostMessage(handles[index], 0x0010, IntPtr.Zero, IntPtr.Zero))
            {
                requested++;
            }
        }

        return requested;
    }

    public static bool HasVisibleWindow()
    {
        return ListVisibleWindows().Count > 0;
    }

    private static List<IntPtr> ListVisibleWindows()
    {
        ProcessIds.Clear();
        Process[] processes = Process.GetProcessesByName("acwebhelper");
        for (int index = 0; index < processes.Length; index++)
        {
            try
            {
                ProcessIds.Add(processes[index].Id);
            }
            finally
            {
                processes[index].Dispose();
            }
        }

        FoundHandles.Clear();
        if (ProcessIds.Count == 0)
        {
            return new List<IntPtr>();
        }

        EnumWindows(WindowCallback, IntPtr.Zero);
        return new List<IntPtr>(FoundHandles);
    }

    private static bool OnWindow(IntPtr handle, IntPtr lParam)
    {
        uint processId;
        GetWindowThreadProcessId(handle, out processId);
        if (!ContainsProcessId((int)processId) || !IsWindowVisible(handle))
        {
            return true;
        }

        FoundHandles.Add(handle);
        return true;
    }

    private static bool ContainsProcessId(int processId)
    {
        for (int index = 0; index < ProcessIds.Count; index++)
        {
            if (ProcessIds[index] == processId)
            {
                return true;
            }
        }

        return false;
    }

    private delegate bool EnumWindowsProc(IntPtr handle, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr handle);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"CiscoBrowserCloser").Type) {
    Add-Type -TypeDefinition $CiscoBrowserSource -Language CSharp
}

# Plain HTTP on a normal site. Connectivity-check hosts such as msftconnecttest.com
# are often allowed through without showing the airline sign-in page.
$Script:TriggerUrl = "http://neverssl.com"
$Script:LinkState = "Unavailable"
$Script:IsOpening = $False
$Script:SsidWarningShown = $False

Function New-FrozenBrush {
    Param(
        [Byte]$Red,
        [Byte]$Green,
        [Byte]$Blue
    )

    $Color = [System.Windows.Media.Color]::FromRgb($Red, $Green, $Blue)
    $Brush = New-Object System.Windows.Media.SolidColorBrush $Color
    $Brush.Freeze()
    Return $Brush
}

Function Show-ActionResult {
    Param(
        [String]$Message,
        [System.Windows.Media.Brush]$Foreground
    )

    $Script:ResultText.Text = $Message
    $Script:ResultText.Foreground = $Foreground
    $Script:ResultText.Visibility = [System.Windows.Visibility]::Visible
}

Function Get-ConnectedWifiLabel {
    $Names = New-Object System.Collections.Generic.List[String]
    Try {
        $NetworkInformation = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
        $Profiles = $NetworkInformation::GetConnectionProfiles()
        ForEach ($Profile in $Profiles) {
            $WlanDetails = $Profile.WlanConnectionProfileDetails
            If ($Null -Eq $WlanDetails) {
                Continue
            }

            $Ssid = [String]$WlanDetails.GetConnectedSsid()
            If ([String]::IsNullOrWhiteSpace($Ssid) -Eq $False) {
                $Names.Add($Ssid)
            }
        }
    }
    Catch {
        If ($Script:SsidWarningShown -Eq $False) {
            Write-Host "[WARN] Could not read the Wi-Fi network name."
            $Script:SsidWarningShown = $True
        }
    }

    If ($Names.Count -Eq 0) {
        Return ""
    }

    Return ("Network: " + ($Names.ToArray() -Join ", "))
}

Function Update-WifiStatus {
    $Snapshot = [WifiMonitor]::Query()
    $Script:LinkState = [String]$Snapshot.State

    Switch ($Script:LinkState) {
        "Connected" {
            $Script:StatusDot.Fill = $Script:ConnectedBrush
            $Script:StatusText.Text = "Wi-Fi connected"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        "RadioOff" {
            $Script:StatusDot.Fill = $Script:WarningBrush
            $Script:StatusText.Text = "Wi-Fi is off"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        "Disconnected" {
            $Script:StatusDot.Fill = $Script:IdleBrush
            $Script:StatusText.Text = "Wi-Fi not connected"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        "NoAdapter" {
            $Script:StatusDot.Fill = $Script:WarningBrush
            $Script:StatusText.Text = "No Wi-Fi adapter"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        Default {
            $Script:StatusDot.Fill = $Script:WarningBrush
            $Script:StatusText.Text = "Wi-Fi status unavailable"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
    }

    If ($Script:LinkState -Eq "Connected") {
        $NetworkLabel = [String](Get-ConnectedWifiLabel)
        If ([String]::IsNullOrWhiteSpace($NetworkLabel) -Eq $False) {
            $Script:NetworkText.Text = $NetworkLabel
        }
    }

    Update-SignInButtonState
}

Function Update-SignInButtonState {
    If ($Null -Eq $Script:OpenSignInButton) {
        Return
    }

    $WifiConnected = $Script:LinkState -Eq "Connected"
    $SignInBusy = $Script:IsOpening -Eq $True
    $Script:OpenSignInButton.IsEnabled = ($WifiConnected -Eq $True) -And ($SignInBusy -Eq $False)
}

Function Get-SignInResultMessage {
    Param(
        [String]$CiscoState
    )

    $Lead = "Opened in your default browser."
    If ($CiscoState -Eq "StillOpen") {
        $Lead = "Opened in your default browser. If the sign-in page does not appear, try again."
    }

    If ($Script:LinkState -Eq "RadioOff") {
        Return ($Lead + " Turn Wi-Fi on to load the sign-in page.")
    }

    If ($Script:LinkState -Eq "Disconnected") {
        Return ($Lead + " Connect to a Wi-Fi network to load the sign-in page.")
    }

    Return $Lead
}

Function Complete-SignInLaunch {
    Param(
        [String]$CiscoState
    )

    Try {
        Start-Process -FilePath $Script:TriggerUrl
        $Message = Get-SignInResultMessage -CiscoState $CiscoState
        $Brush = $Script:SuccessTextBrush
        If (($CiscoState -Eq "StillOpen") -Or ($Script:LinkState -Eq "RadioOff") -Or ($Script:LinkState -Eq "Disconnected")) {
            $Brush = $Script:WarningTextBrush
        }

        Show-ActionResult -Message $Message -Foreground $Brush
    }
    Catch {
        $OpenError = $Error[0].Exception.Message
        Show-ActionResult -Message ("Could not open the default browser. " + $OpenError) -Foreground $Script:ErrorTextBrush
    }
    Finally {
        $Script:Cooldown = New-Object System.Windows.Threading.DispatcherTimer
        $Script:Cooldown.Interval = [TimeSpan]::FromSeconds(1)
        $Script:Cooldown.Add_Tick({
            $Script:Cooldown.Stop()
            $Script:IsOpening = $False
            Update-SignInButtonState
        })
        $Script:Cooldown.Start()
    }
}

Function Complete-SignInAfterCiscoClose {
    If ($Script:CiscoCloseFinished -Eq $True) {
        Return
    }

    $StillOpen = [CiscoBrowserCloser]::HasVisibleWindow()
    $TimedOut = (Get-Date) -Gt $Script:CiscoCloseDeadline
    If (($StillOpen -Eq $True) -And ($TimedOut -Eq $False)) {
        Return
    }

    $Script:CiscoCloseFinished = $True
    If ($Script:CiscoCloseTimer -Ne $Null) {
        $Script:CiscoCloseTimer.Stop()
    }

    $CiscoState = "StillOpen"
    If ($StillOpen -Eq $False) {
        $CiscoState = "Closed"
    }

    Complete-SignInLaunch -CiscoState $CiscoState
}

Function Invoke-SignInPage {
    If ($Script:IsOpening -Eq $True) {
        Return
    }

    $Script:IsOpening = $True
    $Script:OpenSignInButton.IsEnabled = $False
    $CloseRequests = [CiscoBrowserCloser]::RequestClose()
    If ($CloseRequests -Gt 0) {
        Show-ActionResult -Message "Opening the sign-in page..." -Foreground $Script:WarningTextBrush
        $Script:CiscoCloseFinished = $False
        $Script:CiscoCloseDeadline = (Get-Date).AddSeconds(2)
        $Script:CiscoCloseTimer = New-Object System.Windows.Threading.DispatcherTimer
        $Script:CiscoCloseTimer.Interval = [TimeSpan]::FromMilliseconds(100)
        $Script:CiscoCloseTimer.Add_Tick({ Complete-SignInAfterCiscoClose })
        $Script:CiscoCloseTimer.Start()
        Return
    }

    Complete-SignInLaunch -CiscoState "None"
}

Function Close-SignInWindow {
    If ($Script:Timer -Ne $Null) {
        $Script:Timer.Stop()
    }

    If ($Script:CiscoCloseTimer -Ne $Null) {
        $Script:CiscoCloseTimer.Stop()
    }

    If ($Script:OnNetworkChanged -Ne $Null) {
        [System.Net.NetworkInformation.NetworkChange]::Remove_NetworkAddressChanged($Script:OnNetworkChanged)
        [System.Net.NetworkInformation.NetworkChange]::Remove_NetworkAvailabilityChanged($Script:OnNetworkChanged)
    }
}

$Script:ConnectedBrush = New-FrozenBrush -Red 0x1F -Green 0x8A -Blue 0x4C
$Script:IdleBrush = New-FrozenBrush -Red 0x9A -Green 0xA3 -Blue 0xAF
$Script:WarningBrush = New-FrozenBrush -Red 0xC4 -Green 0x7B -Blue 0x00
$Script:SuccessTextBrush = New-FrozenBrush -Red 0x1F -Green 0x6B -Blue 0x3A
$Script:WarningTextBrush = New-FrozenBrush -Red 0x8A -Green 0x4B -Blue 0x08
$Script:ErrorTextBrush = New-FrozenBrush -Red 0xA1 -Green 0x26 -Blue 0x22

$WindowXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Captive portal sign-in"
        Width="440"
        SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        Topmost="True"
        ResizeMode="CanMinimize"
        Background="#F4F6F8"
        FontFamily="Segoe UI"
        FontSize="14"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Display">
    <Window.Resources>
        <Style x:Key="SignInButtonStyle" TargetType="Button">
            <Setter Property="Background" Value="#0B5FFF" />
            <Setter Property="Foreground" Value="White" />
            <Setter Property="FontSize" Value="14" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="Height" Value="40" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                CornerRadius="6"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              TextElement.Foreground="{TemplateBinding Foreground}"
                                              TextElement.FontWeight="{TemplateBinding FontWeight}" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#0848C7" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#063A9E" />
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Border" Property="Background" Value="#C5CDD6" />
                                <Setter Property="Foreground" Value="#F7F8FA" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>

        <TextBlock Text="Captive portal sign-in"
                   FontSize="20"
                   FontWeight="SemiBold"
                   Foreground="#172033" />

        <Border Grid.Row="1"
                Margin="0,16,0,0"
                Background="White"
                BorderBrush="#E1E6EC"
                BorderThickness="1"
                CornerRadius="8"
                Padding="14,12">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="*" />
                </Grid.ColumnDefinitions>
                <Ellipse x:Name="StatusDot"
                         Width="12"
                         Height="12"
                         Fill="#9AA3AF"
                         VerticalAlignment="Center"
                         AutomationProperties.AutomationId="WifiStatusDot" />
                <StackPanel Grid.Column="1" Margin="12,0,0,0">
                    <TextBlock x:Name="StatusText"
                               Text="Checking Wi-Fi..."
                               FontWeight="SemiBold"
                               Foreground="#172033"
                               AutomationProperties.AutomationId="WifiStatusText" />
                    <TextBlock x:Name="NetworkText"
                               Margin="0,3,0,0"
                               Foreground="#5E6A78"
                               TextWrapping="Wrap"
                               AutomationProperties.AutomationId="NetworkText" />
                </StackPanel>
            </Grid>
        </Border>

        <Button x:Name="OpenSignInButton"
                Grid.Row="2"
                Margin="0,16,0,0"
                Style="{StaticResource SignInButtonStyle}"
                Content="Open sign-in page"
                IsEnabled="False"
                IsDefault="True"
                AutomationProperties.AutomationId="OpenSignInButton"
                AutomationProperties.Name="Open sign-in page" />

        <TextBlock x:Name="ResultText"
                   Grid.Row="3"
                   Margin="0,12,0,0"
                   TextWrapping="Wrap"
                   Visibility="Collapsed"
                   AutomationProperties.AutomationId="ActionResultText" />

        <TextBlock Grid.Row="4"
                   Margin="0,12,0,0"
                   Foreground="#5E6A78"
                   FontSize="12"
                   TextWrapping="Wrap"
                   Text="Connect to the desired Wi-Fi network, then click Open sign-in page to launch the authentication page." />
    </Grid>
</Window>
'@

$Script:Window = [System.Windows.Markup.XamlReader]::Parse($WindowXaml)
$Script:StatusDot = $Script:Window.FindName("StatusDot")
$Script:StatusText = $Script:Window.FindName("StatusText")
$Script:NetworkText = $Script:Window.FindName("NetworkText")
$Script:OpenSignInButton = $Script:Window.FindName("OpenSignInButton")
$Script:ResultText = $Script:Window.FindName("ResultText")

If (($Null -Eq $Script:StatusDot) -Or ($Null -Eq $Script:StatusText) -Or ($Null -Eq $Script:NetworkText) -Or ($Null -Eq $Script:OpenSignInButton) -Or ($Null -Eq $Script:ResultText)) {
    Write-Error "[ERROR] The sign-in window could not be loaded."
    Exit 1
}

$Script:OpenSignInButton.Add_Click({ Invoke-SignInPage })
$Script:Window.Add_Loaded({
    Update-WifiStatus
    $Script:Timer.Start()
})
$Script:Window.Add_Activated({ Update-WifiStatus })
$Script:Window.Add_Closed({ Close-SignInWindow })

$Script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$Script:Timer.Interval = [TimeSpan]::FromSeconds(2)
$Script:Timer.Add_Tick({ Update-WifiStatus })

$Script:OnNetworkChanged = {
    If ($Script:Window -Ne $Null) {
        $Script:Window.Dispatcher.BeginInvoke([System.Action]{ Update-WifiStatus }) | Out-Null
    }
}
[System.Net.NetworkInformation.NetworkChange]::Add_NetworkAddressChanged($Script:OnNetworkChanged)
[System.Net.NetworkInformation.NetworkChange]::Add_NetworkAvailabilityChanged($Script:OnNetworkChanged)

Write-Host "[INFO] Opening the captive portal sign-in window."
$Script:Window.ShowDialog() | Out-Null
Write-Host "[INFO] Captive portal sign-in window closed."
Exit 0
