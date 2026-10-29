#Requires -Version 5.1

Param(
    [Switch]$StaHost
)

$ErrorActionPreference = "Stop"
$Script:LogLock = New-Object System.Object
$Script:LastLoggedLinkState = ""
$TempFolder = $Env:TEMP
If ([String]::IsNullOrWhiteSpace($TempFolder)) {
    $TempFolder = [System.IO.Path]::GetTempPath()
}
$Script:LogPath = Join-Path $TempFolder "LaunchCaptivePortalAuthPage.log"

Function Write-SignInLog {
    Param(
        [String]$Message
    )

    If ([String]::IsNullOrWhiteSpace($Script:LogPath)) {
        Return
    }

    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $Line = "[" + $Stamp + "] " + $Message + [System.Environment]::NewLine
    [System.Threading.Monitor]::Enter($Script:LogLock)
    Try {
        $Utf8 = New-Object System.Text.UTF8Encoding $False
        [System.IO.File]::AppendAllText($Script:LogPath, $Line, $Utf8)
    }
    Catch {
    }
    Finally {
        [System.Threading.Monitor]::Exit($Script:LogLock)
    }
}

[System.AppDomain]::CurrentDomain.Add_UnhandledException({
    Param($Sender, $EventArgs)
    $ExceptionText = ""
    If ($Null -Ne $EventArgs.ExceptionObject) {
        $ExceptionText = $EventArgs.ExceptionObject.ToString()
    }
    Write-SignInLog ("[ERROR] Process unhandled exception. Terminating=" + $EventArgs.IsTerminating + ". " + $ExceptionText)
})

If ([String]::IsNullOrWhiteSpace($PSCommandPath)) {
    Write-SignInLog "[ERROR] Run this script from a file path."
    Write-Error "[ERROR] Run this script from a file path."
    Exit 1
}

$IsDesktopHost = $PSVersionTable.PSEdition -Eq "Desktop"
$IsStaThread = [System.Threading.Thread]::CurrentThread.ApartmentState -Eq [System.Threading.ApartmentState]::STA
If (($IsDesktopHost -Eq $False) -Or ($IsStaThread -Eq $False)) {
    If ($StaHost -Eq $True) {
        Write-SignInLog "[ERROR] WPF requires Windows PowerShell 5.1 running in STA mode."
        Write-Error "[ERROR] WPF requires Windows PowerShell 5.1 running in STA mode."
        Exit 1
    }

    Write-SignInLog "[INFO] Restarting in Windows PowerShell STA. This process will exit."
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

Write-SignInLog ("[INFO] Sign-in script started. PID=" + $PID + ". ErrorAction=Stop.")

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$WifiMonitorSource = @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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
                List<Guid> connectedInterfaces = new List<Guid>();
                bool anyConnecting = false;
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
                        connectedInterfaces.Add(interfaceGuid);
                        connectedNames.Add(QueryConnectedName(handle, interfaceGuid));
                        continue;
                    }

                    if (state == 5 || state == 6 || state == 7)
                    {
                        anyConnecting = true;
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

                if (connectedInterfaces.Count > 0)
                {
                    string names = JoinNetworkNames(connectedNames);
                    if (!HasUsableAddress(connectedInterfaces))
                    {
                        if (names.StartsWith("Network: "))
                        {
                            return new WifiSnapshot("Connecting", names);
                        }

                        return new WifiSnapshot("Connecting", "Waiting for an address from the network.");
                    }

                    return new WifiSnapshot("Connected", names);
                }

                if (anyConnecting)
                {
                    return new WifiSnapshot("Connecting", "Connecting to the Wi-Fi network.");
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

    private static bool HasUsableAddress(List<Guid> interfaceGuids)
    {
        try
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            for (int index = 0; index < interfaceGuids.Count; index++)
            {
                string withBraces = interfaceGuids[index].ToString("B");
                string plain = interfaceGuids[index].ToString("D");
                for (int adapterIndex = 0; adapterIndex < adapters.Length; adapterIndex++)
                {
                    NetworkInterface adapter = adapters[adapterIndex];
                    if (adapter.NetworkInterfaceType != NetworkInterfaceType.Wireless80211)
                    {
                        continue;
                    }

                    if (adapter.OperationalStatus != OperationalStatus.Up)
                    {
                        continue;
                    }

                    if (!string.Equals(adapter.Id, withBraces, StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(adapter.Id, plain, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                    {
                        if (IsUsableAddress(address.Address))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            return false;
        }

        return false;
    }

    private static bool IsUsableAddress(IPAddress address)
    {
        if (address == null || IPAddress.IsLoopback(address))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length != 4 || bytes[0] == 0)
            {
                return false;
            }

            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !address.IsIPv6LinkLocal;
        }

        return false;
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

$CiscoFailoverNoticeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class CiscoFailoverNotice
{
    private const string NoticeMarker = "retry logging on with the service provider";
    private static bool FoundNotice;
    private static IntPtr OkButton;

    public static bool TryDismiss()
    {
        try
        {
            FoundNotice = false;
            OkButton = IntPtr.Zero;
            EnumWindows(OnWindow, IntPtr.Zero);
            if (!FoundNotice || OkButton == IntPtr.Zero)
            {
                return false;
            }

            PostMessage(OkButton, 0x00F5, IntPtr.Zero, IntPtr.Zero);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool OnWindow(IntPtr handle, IntPtr lParam)
    {
        if (!IsWindowVisible(handle))
        {
            return true;
        }

        FoundNotice = false;
        OkButton = IntPtr.Zero;
        EnumChildWindows(handle, OnChild, IntPtr.Zero);
        if (FoundNotice && OkButton != IntPtr.Zero)
        {
            return false;
        }

        FoundNotice = false;
        OkButton = IntPtr.Zero;
        return true;
    }

    private static bool OnChild(IntPtr handle, IntPtr lParam)
    {
        string text = ReadText(handle);
        if (text.IndexOf(NoticeMarker, StringComparison.OrdinalIgnoreCase) >= 0)
        {
            FoundNotice = true;
        }

        if (IsOkButton(text) && IsButton(handle))
        {
            OkButton = handle;
        }

        return true;
    }

    private static bool IsOkButton(string name)
    {
        if (name == null)
        {
            return false;
        }

        string trimmed = name.Replace("&", "").Trim();
        return string.Equals(trimmed, "OK", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsButton(IntPtr handle)
    {
        string className = ReadClassName(handle);
        if (string.Equals(className, "Button", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return className.IndexOf("BUTTON", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string ReadText(IntPtr handle)
    {
        StringBuilder text = new StringBuilder(2048);
        GetWindowText(handle, text, text.Capacity);
        return text.ToString();
    }

    private static string ReadClassName(IntPtr handle)
    {
        StringBuilder text = new StringBuilder(256);
        GetClassName(handle, text, text.Capacity);
        return text.ToString();
    }

    private delegate bool EnumWindowsProc(IntPtr handle, IntPtr lParam);
    private delegate bool EnumChildProc(IntPtr handle, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumChildWindows(IntPtr parent, EnumChildProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr handle);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr handle, StringBuilder text, int maxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr handle, StringBuilder text, int maxCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"CiscoFailoverNotice").Type) {
    Add-Type -TypeDefinition $CiscoFailoverNoticeSource -Language CSharp
}

$NetworkChangeRelaySource = @'
using System;
using System.Net.NetworkInformation;
using System.Windows.Threading;

public static class NetworkChangeRelay
{
    private static bool IsListening;
    private static Dispatcher Dispatcher;
    private static Action Callback;

    public static void Start(Dispatcher dispatcher, Action callback)
    {
        Stop();
        Dispatcher = dispatcher;
        Callback = callback;
        NetworkChange.NetworkAddressChanged += OnAddressChanged;
        NetworkChange.NetworkAvailabilityChanged += OnAvailabilityChanged;
        IsListening = true;
    }

    public static void Stop()
    {
        if (!IsListening)
        {
            return;
        }

        NetworkChange.NetworkAddressChanged -= OnAddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnAvailabilityChanged;
        IsListening = false;
        Callback = null;
        Dispatcher = null;
    }

    private static void OnAddressChanged(object sender, EventArgs e)
    {
        Dispatch();
    }

    private static void OnAvailabilityChanged(object sender, NetworkAvailabilityEventArgs e)
    {
        Dispatch();
    }

    private static void Dispatch()
    {
        Dispatcher dispatcher = Dispatcher;
        Action callback = Callback;
        if (dispatcher == null || callback == null)
        {
            return;
        }

        dispatcher.BeginInvoke(callback);
    }
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"NetworkChangeRelay").Type) {
    Add-Type -TypeDefinition $NetworkChangeRelaySource -ReferencedAssemblies "WindowsBase" -Language CSharp
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
    Try {
        $Snapshot = [WifiMonitor]::Query()
        $Script:LinkState = [String]$Snapshot.State
        If ($Script:LinkState -Ne $Script:LastLoggedLinkState) {
            Write-SignInLog ("[INFO] Wi-Fi state is " + $Script:LinkState + ". " + [String]$Snapshot.Detail)
            $Script:LastLoggedLinkState = $Script:LinkState
        }

        Switch ($Script:LinkState) {
        "Connected" {
            $Script:StatusDot.Fill = $Script:ConnectedBrush
            $Script:StatusText.Text = "Wi-Fi connected"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        "Connecting" {
            $Script:StatusDot.Fill = $Script:WarningBrush
            $Script:StatusText.Text = "Wi-Fi connecting"
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
    Catch {
        $StatusError = [String]$Error[0]
        Write-SignInLog ("[ERROR] Wi-Fi status update failed: " + $StatusError)
        Throw
    }
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

    $Lead = "Launching the authentication page in your default browser."
    If ($CiscoState -Eq "StillOpen") {
        $Lead = "Launching the authentication page in your default browser. If the sign-in page does not appear, try again."
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
    Write-SignInLog "[INFO] Open sign-in page clicked."
    Start-FailoverNoticeMonitor
    $CloseRequests = [CiscoBrowserCloser]::RequestClose()
    Write-SignInLog ("[INFO] Cisco browser close requests=" + $CloseRequests)
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

Function Move-SignInWindowToTopRight {
    $Script:Window.UpdateLayout()
    $WindowWidth = $Script:Window.ActualWidth
    $WindowHeight = $Script:Window.ActualHeight
    If ($WindowWidth -Le 0) {
        $WindowWidth = $Script:Window.Width
    }
    If ($WindowHeight -Le 0) {
        $WindowHeight = 240
    }

    $WorkArea = [System.Windows.SystemParameters]::WorkArea
    $EdgeGap = 16
    $Script:Window.Left = $WorkArea.Right - $WindowWidth - $EdgeGap
    $Script:Window.Top = $WorkArea.Top + $EdgeGap
}

Function Start-FailoverNoticeMonitor {
    If ($Script:FailoverNoticeTimer -Ne $Null) {
        $Script:FailoverNoticeTimer.Stop()
    }

    $Script:FailoverNoticeDeadline = (Get-Date).AddSeconds(5)
    $Script:FailoverNoticeTimer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:FailoverNoticeTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $Script:FailoverNoticeTimer.Add_Tick({ Update-FailoverNoticeMonitor })
    $Script:FailoverNoticeTimer.Start()
    Write-SignInLog "[INFO] Watching for the Cisco failover notice for 5 seconds."
}

Function Update-FailoverNoticeMonitor {
    Try {
        If ((Get-Date) -Gt $Script:FailoverNoticeDeadline) {
            $Script:FailoverNoticeTimer.Stop()
            Write-SignInLog "[INFO] Cisco failover notice was not shown. Monitor stopped."
            Return
        }

        If ([CiscoFailoverNotice]::TryDismiss() -Eq $True) {
            $Script:FailoverNoticeTimer.Stop()
            Write-SignInLog "[INFO] Cisco failover notice was dismissed."
        }
    }
    Catch {
        If ($Script:FailoverNoticeTimer -Ne $Null) {
            $Script:FailoverNoticeTimer.Stop()
        }

        Write-SignInLog ("[ERROR] Cisco failover notice monitor failed: " + [String]$Error[0])
    }
}

Function Close-SignInWindow {
    If ($Script:Timer -Ne $Null) {
        $Script:Timer.Stop()
    }

    If ($Script:CiscoCloseTimer -Ne $Null) {
        $Script:CiscoCloseTimer.Stop()
    }

    If ($Null -Ne ([System.Management.Automation.PSTypeName]"NetworkChangeRelay").Type) {
        [NetworkChangeRelay]::Stop()
    }

    If ($Script:FailoverNoticeTimer -Ne $Null) {
        $Script:FailoverNoticeTimer.Stop()
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
        Title="Captive Portal Connection Helper"
        Width="460"
        SizeToContent="Height"
        WindowStartupLocation="Manual"
        Topmost="True"
        ResizeMode="CanMinimize"
        Background="#F5F6F8"
        FontFamily="Segoe UI"
        FontSize="13"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Display">
    <Window.Resources>
        <Style x:Key="SignInButtonStyle" TargetType="Button">
            <Setter Property="Background" Value="#CA2420" />
            <Setter Property="Foreground" Value="White" />
            <Setter Property="FontSize" Value="13" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="Height" Value="36" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                CornerRadius="4"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              TextElement.Foreground="{TemplateBinding Foreground}"
                                              TextElement.FontWeight="{TemplateBinding FontWeight}" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#A81E1B" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#8E1916" />
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Border" Property="Background" Value="#E6E9ED" />
                                <Setter Property="Foreground" Value="#6B7380" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Grid Margin="24,22,24,20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>

        <TextBlock Text="Captive Portal Connection Helper"
                   FontSize="18"
                   FontWeight="SemiBold"
                   Foreground="#1A2332" />

        <TextBlock Grid.Row="1"
                   Margin="0,6,0,0"
                   Foreground="#5E6874"
                   FontSize="12"
                   TextWrapping="Wrap"
                   Text="Connect to the desired Wi-Fi network, then click Launch Logon Page to launch the authentication page." />

        <Border Grid.Row="2"
                Margin="0,18,0,0"
                Background="White"
                BorderBrush="#D5DBE3"
                BorderThickness="1"
                CornerRadius="6"
                Padding="14,12">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="*" />
                </Grid.ColumnDefinitions>
                <Ellipse x:Name="StatusDot"
                         Width="16"
                         Height="16"
                         Margin="0,1,0,0"
                         Fill="#9AA3AF"
                         VerticalAlignment="Top"
                         AutomationProperties.AutomationId="WifiStatusDot" />
                <StackPanel Grid.Column="1" Margin="12,0,0,0">
                    <TextBlock x:Name="StatusText"
                               Text="Checking Wi-Fi..."
                               FontSize="13"
                               FontWeight="SemiBold"
                               Foreground="#1A2332"
                               AutomationProperties.AutomationId="WifiStatusText" />
                    <TextBlock x:Name="NetworkText"
                               Margin="0,2,0,0"
                               FontSize="12"
                               Foreground="#5E6874"
                               TextWrapping="Wrap"
                               AutomationProperties.AutomationId="NetworkText" />
                </StackPanel>
            </Grid>
        </Border>

        <Button x:Name="OpenSignInButton"
                Grid.Row="3"
                Margin="0,16,0,0"
                Style="{StaticResource SignInButtonStyle}"
                Content="Launch Logon Page"
                IsEnabled="False"
                IsDefault="True"
                AutomationProperties.AutomationId="OpenSignInButton"
                AutomationProperties.Name="Launch Logon Page" />

        <TextBlock x:Name="ResultText"
                   Grid.Row="4"
                   Margin="0,12,0,0"
                   FontSize="12"
                   TextWrapping="Wrap"
                   Visibility="Collapsed"
                   AutomationProperties.AutomationId="ActionResultText" />
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
    Write-SignInLog "[ERROR] The sign-in window could not be loaded."
    Write-Error "[ERROR] The sign-in window could not be loaded."
    Exit 1
}

$Script:OpenSignInButton.Add_Click({ Invoke-SignInPage })
$Script:Window.Add_Loaded({
    Move-SignInWindowToTopRight
    Write-SignInLog "[INFO] Sign-in window loaded."
    Update-WifiStatus
    $Script:Timer.Start()
})
$Script:Window.Add_Activated({ Update-WifiStatus })
$Script:Window.Add_Closed({
    Write-SignInLog "[INFO] Sign-in window Closed event."
    Close-SignInWindow
})
$Script:Window.Dispatcher.Add_UnhandledException({
    Param($Sender, $EventArgs)
    $ExceptionText = ""
    If ($Null -Ne $EventArgs.Exception) {
        $ExceptionText = $EventArgs.Exception.ToString()
    }
    Write-SignInLog ("[ERROR] Dispatcher unhandled exception: " + $ExceptionText)
})
$Script:Window.Dispatcher.Add_ShutdownStarted({
    Write-SignInLog "[INFO] Dispatcher shutdown started."
})

$Script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$Script:Timer.Interval = [TimeSpan]::FromSeconds(2)
$Script:Timer.Add_Tick({ Update-WifiStatus })

$Script:OnNetworkChanged = {
    Write-SignInLog "[INFO] Network change notification."
    Update-WifiStatus
}
[NetworkChangeRelay]::Start($Script:Window.Dispatcher, [System.Action]$Script:OnNetworkChanged)

Write-SignInLog "[INFO] Opening the captive portal sign-in window."
Write-Host "[INFO] Opening the captive portal sign-in window."
Try {
    $Script:Window.ShowDialog() | Out-Null
    Write-SignInLog "[INFO] ShowDialog returned."
}
Catch {
    $DialogError = [String]$Error[0]
    Write-SignInLog ("[ERROR] ShowDialog ended with an error: " + $DialogError)
    Write-Error "[ERROR] ShowDialog ended with an error: $DialogError"
}
Write-SignInLog "[INFO] Sign-in script is exiting."
Write-Host "[INFO] Captive portal sign-in window closed."
Exit 0
