using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

internal sealed class ReleaseLauncher : Form
{
    private readonly string rootDir;
    private readonly string gameDir;
    private readonly string gameExe;
    private readonly string startLocal;
    private readonly string assetRoot;
    private readonly string pythonExe;
    private readonly string logFile;

    private readonly TextBox localAccountBox;
    private readonly TextBox localTicketBox;
    private readonly TextBox remoteServerBox;
    private readonly TextBox remoteAccountBox;
    private readonly TextBox remotePasswordBox;
    private readonly TextBox logBox;

    private Process localProcess;
    private bool gameLaunched;
    private string[] pendingGameArgs = new string[0];
    private Timer launchTimer;

    private const string DefaultAccount = "100000001";
    private const string DefaultTicket = "AAAAILocalOfflineTicket0000000000000000000000000";
    private const string DefaultServer = "127.0.0.1:15000";

    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new ReleaseLauncher());
    }

    private ReleaseLauncher()
    {
        string exeDir = Path.GetDirectoryName(Application.ExecutablePath);
        if (Directory.Exists(Path.Combine(exeDir, "game")))
        {
            rootDir = exeDir;
        }
        else
        {
            rootDir = Directory.GetParent(exeDir).FullName;
        }

        gameDir = Path.Combine(rootDir, "game");
        gameExe = Path.Combine(gameDir, "FinalCombat.exe");
        startLocal = Path.Combine(rootDir, "launcher", "start_local.py");
        assetRoot = Path.Combine(rootDir, "protocol_assets");
        pythonExe = File.Exists(@"C:\python3.13.13\python.exe") ? @"C:\python3.13.13\python.exe" : "python";
        logFile = Path.Combine(rootDir, "launcher_runtime.log");

        Text = "FinalCombat Local Launcher";
        Size = new Size(900, 600);
        MinimumSize = new Size(820, 520);
        StartPosition = FormStartPosition.CenterScreen;

        TableLayoutPanel main = new TableLayoutPanel();
        main.Dock = DockStyle.Fill;
        main.Padding = new Padding(12);
        main.RowCount = 2;
        main.ColumnCount = 1;
        main.RowStyles.Add(new RowStyle(SizeType.Absolute, 240));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(main);

        TableLayoutPanel columns = new TableLayoutPanel();
        columns.Dock = DockStyle.Fill;
        columns.ColumnCount = 2;
        columns.RowCount = 1;
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        main.Controls.Add(columns, 0, 0);

        GroupBox localGroup = new GroupBox();
        localGroup.Text = "Single-player direct map";
        localGroup.Dock = DockStyle.Fill;
        localGroup.Padding = new Padding(12);
        columns.Controls.Add(localGroup, 0, 0);

        GroupBox remoteGroup = new GroupBox();
        remoteGroup.Text = "Developer server";
        remoteGroup.Dock = DockStyle.Fill;
        remoteGroup.Padding = new Padding(12);
        columns.Controls.Add(remoteGroup, 1, 0);

        FlowLayoutPanel localPanel = MakeTopDownPanel();
        localGroup.Controls.Add(localPanel);
        FlowLayoutPanel remotePanel = MakeTopDownPanel();
        remoteGroup.Controls.Add(remotePanel);

        localAccountBox = AddLabeledTextBox(localPanel, "Account", Env("FC_RELEASE_ACCOUNT", DefaultAccount), false);
        localTicketBox = AddLabeledTextBox(localPanel, "Ticket", Env("FC_RELEASE_TICKET", DefaultTicket), false);

        Button startLocalButton = MakeButton("Start local single-player");
        startLocalButton.Click += delegate { StartLocalSinglePlayer(); };
        localPanel.Controls.Add(startLocalButton);

        Button stopLocalButton = MakeButton("Stop local services");
        stopLocalButton.Click += delegate { StopLocalServices(); };
        localPanel.Controls.Add(stopLocalButton);

        remoteServerBox = AddLabeledTextBox(remotePanel, "Server IP:port", Env("FC_RELEASE_SERVER", DefaultServer), false);
        remoteAccountBox = AddLabeledTextBox(remotePanel, "Account", Env("FC_RELEASE_ACCOUNT", DefaultAccount), false);
        remotePasswordBox = AddLabeledTextBox(remotePanel, "Password / ticket", "", true);

        Button remoteButton = MakeButton("Login developer server");
        remoteButton.Click += delegate { StartRemoteServer(); };
        remotePanel.Controls.Add(remoteButton);

        Panel logPanel = new Panel();
        logPanel.Dock = DockStyle.Fill;
        main.Controls.Add(logPanel, 0, 1);

        Label logLabel = new Label();
        logLabel.Text = "Runtime log";
        logLabel.AutoSize = true;
        logLabel.Dock = DockStyle.Top;
        logPanel.Controls.Add(logLabel);

        logBox = new TextBox();
        logBox.Multiline = true;
        logBox.ScrollBars = ScrollBars.Vertical;
        logBox.ReadOnly = true;
        logBox.Dock = DockStyle.Fill;
        logBox.Font = new Font("Consolas", 9);
        logPanel.Controls.Add(logBox);
        logBox.BringToFront();

        FormClosing += delegate { StopOwnedLocalProcess(); };
        Log("Release root: " + rootDir);
        Log("Python: " + pythonExe);
    }

    private static string Env(string name, string fallback)
    {
        string value = Environment.GetEnvironmentVariable(name);
        return String.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static FlowLayoutPanel MakeTopDownPanel()
    {
        FlowLayoutPanel panel = new FlowLayoutPanel();
        panel.Dock = DockStyle.Fill;
        panel.FlowDirection = FlowDirection.TopDown;
        panel.WrapContents = false;
        panel.AutoScroll = true;
        return panel;
    }

    private static Button MakeButton(string text)
    {
        Button button = new Button();
        button.Text = text;
        button.Width = 360;
        button.Margin = new Padding(0, 12, 0, 2);
        return button;
    }

    private static TextBox AddLabeledTextBox(Control parent, string label, string value, bool password)
    {
        Label labelControl = new Label();
        labelControl.Text = label;
        labelControl.AutoSize = true;
        labelControl.Margin = new Padding(0, 8, 0, 2);
        parent.Controls.Add(labelControl);

        TextBox box = new TextBox();
        box.Text = value;
        box.Width = 360;
        if (password)
        {
            box.UseSystemPasswordChar = true;
        }
        parent.Controls.Add(box);
        return box;
    }

    private void Log(string message)
    {
        string safe = Mask(message);
        try
        {
            File.AppendAllText(logFile, "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + safe + Environment.NewLine, Encoding.UTF8);
        }
        catch
        {
        }

        try
        {
            if (IsDisposed || logBox == null || logBox.IsDisposed)
            {
                return;
            }
            if (logBox.InvokeRequired)
            {
                BeginInvoke(new Action<string>(AppendLog), safe);
            }
            else
            {
                AppendLog(safe);
            }
        }
        catch
        {
        }
    }

    private void AppendLog(string message)
    {
        logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);
        logBox.SelectionStart = logBox.TextLength;
        logBox.ScrollToCaret();
    }

    private static string Mask(string message)
    {
        string masked = Regex.Replace(message, @"(-login\s+)\S+", "$1<redacted>");
        return Regex.Replace(masked, @"AAAA[A-Za-z0-9+/=]{20,}", "<ticket>");
    }

    private bool AssertGameExists()
    {
        if (!File.Exists(gameExe))
        {
            MessageBox.Show("Game file not found: " + gameExe, "Missing game file", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
        return true;
    }

    private void StartLocalSinglePlayer()
    {
        try
        {
            if (!AssertGameExists())
            {
                return;
            }

            string account = String.IsNullOrWhiteSpace(localAccountBox.Text) ? DefaultAccount : localAccountBox.Text.Trim();
            string ticket = String.IsNullOrWhiteSpace(localTicketBox.Text) ? DefaultTicket : localTicketBox.Text.Trim();
            pendingGameArgs = BuildGameArgs(account, ticket, "127.0.0.1", "15000");

            if (localProcess != null && !localProcess.HasExited)
            {
                Log("Local services are already running; launching game.");
                LaunchGame(pendingGameArgs);
                return;
            }

            List<string> busyPorts = GetBusyLocalPorts();
            if (busyPorts.Count > 0)
            {
                if (busyPorts.Count == 4)
                {
                    Log("Required local ports already have listeners: " + String.Join(", ", busyPorts.ToArray()) + ". Launching game against existing local services.");
                    LaunchGame(pendingGameArgs);
                    return;
                }

                string message = "Some required local ports are already in use: " + String.Join(", ", busyPorts.ToArray()) + ". Close the conflicting process and try again.";
                Log(message);
                MessageBox.Show(message, "Ports busy", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            gameLaunched = false;
            StartLocalProcess(account, ticket);
            ScheduleGameLaunch();
        }
        catch (Exception ex)
        {
            Log("Start local failed: " + ex.Message);
            MessageBox.Show(ex.Message, "Start local failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void StartLocalProcess(string account, string ticket)
    {
        string[] args = new string[]
        {
            startLocal,
            "--asset-root", assetRoot,
            "--asset-profile", "singleplayer_direct",
            "--account", account,
            "--ticket", ticket,
            "--server-name", "FinalCombat",
            "--capture-dir=",
            "--python", pythonExe
        };

        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = pythonExe;
        psi.Arguments = JoinArgs(args);
        psi.WorkingDirectory = rootDir;
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.CreateNoWindow = true;

        Process proc = new Process();
        proc.StartInfo = psi;
        proc.EnableRaisingEvents = true;
        proc.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
        {
            if (!String.IsNullOrEmpty(e.Data))
            {
                Log(e.Data);
            }
        };
        proc.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
        {
            if (!String.IsNullOrEmpty(e.Data))
            {
                Log(e.Data);
            }
        };
        proc.Exited += delegate(object sender, EventArgs e)
        {
            Log("Local service process exited: code=" + proc.ExitCode);
            if (!gameLaunched)
            {
                BeginInvoke(new Action(delegate
                {
                    MessageBox.Show("Local services exited before the game was launched.\r\nSee launcher_runtime.log in the release folder.", "Local service exited", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }));
            }
        };

        Log("Starting local auth, proxy, game, and channel services");
        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        localProcess = proc;
    }

    private void ScheduleGameLaunch()
    {
        if (launchTimer != null)
        {
            launchTimer.Stop();
            launchTimer.Dispose();
        }
        launchTimer = new Timer();
        launchTimer.Interval = 2500;
        launchTimer.Tick += delegate
        {
            launchTimer.Stop();
            launchTimer.Dispose();
            launchTimer = null;
            if (localProcess != null && !localProcess.HasExited && !gameLaunched)
            {
                gameLaunched = true;
                LaunchGame(pendingGameArgs);
            }
            else if (localProcess != null && localProcess.HasExited)
            {
                Log("Local services exited before launch timer fired: code=" + localProcess.ExitCode);
            }
        };
        launchTimer.Start();
    }

    private static string[] BuildGameArgs(string account, string ticket, string host, string port)
    {
        return new string[]
        {
            "-info", account,
            "-login", ticket,
            "-proxysvrip", host,
            "-proxysvrport", port,
            "-servername", "FinalCombat",
            "-serverid", "1"
        };
    }

    private void LaunchGame(string[] gameArgs)
    {
        if (!AssertGameExists())
        {
            return;
        }
        PrepareGameConfig();
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = gameExe;
        psi.WorkingDirectory = gameDir;
        psi.UseShellExecute = true;
        psi.Arguments = JoinArgs(gameArgs);
        Log("Launching game: " + gameExe + " " + psi.Arguments);
        Process.Start(psi);
    }

    private void PrepareGameConfig()
    {
        try
        {
            Directory.CreateDirectory(Path.Combine(gameDir, "defend", "cfg"));
            string defendCfg = Path.Combine(gameDir, "defend", "cfg", "cfg.ini");
            string defendText =
                "[Defend]\r\n" +
                "GameId=000045\r\n" +
                "GamePath=" + gameDir + "\r\n" +
                "DefendPath=" + gameDir + "\r\n" +
                "DriverPath=" + gameDir + "\r\n" +
                "Update=0\r\n" +
                "Enable=1\r\n";
            File.WriteAllText(defendCfg, defendText, Encoding.Default);

            string configText =
                "[update]\r\n" +
                "LoginMain_Version=0100010045\r\n" +
                "updateExe_Version=0100010008\r\n" +
                "patchDll_Version=0100000004\r\n" +
                "Defend_version=0101000004\r\n" +
                "updateIni_Url=http://127.0.0.1:18090/update.ini\r\n" +
                "srvlsturl=http://127.0.0.1:18090/servers.txt\r\n" +
                "\r\n" +
                "[Game]\r\n" +
                "gameid=000045\r\n" +
                "account=100000001\r\n" +
                "isSaveAccount=0\r\n" +
                "patchurl=\r\n" +
                "\r\n" +
                "[GameClientUpdate]\r\n" +
                "\r\n" +
                "[report]\r\n" +
                "hardwaretime=\r\n" +
                "personinfotime=\r\n" +
                "\r\n" +
                "[init]\r\n" +
                "initcount=\r\n" +
                "webres=0\r\n" +
                "\r\n" +
                "[DownLoadParam]\r\n" +
                "DirectUrl=1\r\n" +
                "TimeOutMillSec=5000\r\n" +
                "Url0=http://127.0.0.1:18090/assets/\r\n" +
                "Url1=http://127.0.0.1:18090/assets/\r\n" +
                "\r\n" +
                "[url]\r\n" +
                "Url0=http://127.0.0.1:18090/assets/\r\n" +
                "Url1=http://127.0.0.1:18090/assets/\r\n" +
                "DirectUrl=http://127.0.0.1:18090/assets/\r\n" +
                "\r\n" +
                "[WEB]\r\n" +
                "DirectUrl=http://127.0.0.1:18090/assets/\r\n" +
                "URL1=http://127.0.0.1:18090/assets/\r\n" +
                "URL2=http://127.0.0.1:18090/assets/\r\n";
            File.WriteAllText(Path.Combine(gameDir, "config.ini"), configText, Encoding.Default);

            string paramText =
                "[personinfo]\r\n" +
                "maxcount=10\r\n" +
                "[login_web]\r\n" +
                "url=http://127.0.0.1:18090/client/loginer/xml_data_v1.0.xml\r\n" +
                "sessurl=http://127.0.0.1:18090/synchro?\r\n" +
                "[corp_update]\r\n" +
                "url=http://127.0.0.1:18090/sloginfilelist.txt\r\n" +
                "[plugin]\r\n" +
                "settiptime=\r\n" +
                "seturl=http://127.0.0.1:18090/TClick?cf=2&gs=xunleidcf&tt=&linkid=local\r\n" +
                "[XLGameDefendSV]\r\n" +
                "update=0\r\n" +
                "md5=217b1d684ac4eeda4f630cf9c7d3c849\r\n" +
                "[GameServer]\r\n" +
                "IP=127.0.0.1\r\n" +
                "Port=9000\r\n";
            File.WriteAllText(Path.Combine(gameDir, "param.ini"), paramText, Encoding.Default);
            UpdateLoginFileList();
            string avitalDir = Path.Combine(gameDir, "avital");
            string avitalPicDir = Path.Combine(avitalDir, "pic");
            Directory.CreateDirectory(avitalDir);
            Directory.CreateDirectory(avitalPicDir);

            string avitalConfig =
                "[DownLoadParam]\r\n" +
                "DirectUrl=1\r\n" +
                "TimeOutMillSec=5000\r\n" +
                "Url0=http://127.0.0.1:18090/apex/\r\n" +
                "Url1=http://127.0.0.1:18090/apex/\r\n" +
                "\r\n" +
                "[url]\r\n" +
                "Url0=http://127.0.0.1:18090/apex/\r\n" +
                "Url1=http://127.0.0.1:18090/apex/\r\n" +
                "DirectUrl=http://127.0.0.1:18090/apex/\r\n" +
                "\r\n" +
                "[WEB]\r\n" +
                "DirectUrl=http://127.0.0.1:18090/apex/\r\n" +
                "URL1=http://127.0.0.1:18090/apex/\r\n" +
                "URL2=http://127.0.0.1:18090/apex/\r\n";
            File.WriteAllText(Path.Combine(avitalDir, "config.ini"), avitalConfig, Encoding.Default);

            string errConfig =
                "[BUTTON]\r\n" +
                "OK=OK\r\n" +
                "\r\n" +
                "[CAPTION]\r\n" +
                "Caption=ApexProtect\r\n" +
                "\r\n" +
                "[WEB]\r\n" +
                "URL= \r\n" +
                "NUMLIST= \r\n" +
                "\r\n" +
                "[TEXT]\r\n" +
                "10000=Game initialization failed\r\n" +
                "11000=Failed to update files from server\r\n" +
                "11022=File update failed; server file missing\r\n" +
                "11030=Network timeout\r\n" +
                "11035=Connection failed\r\n" +
                "11046=Server does not support resume\r\n" +
                "11051=Check firewall or network connection\r\n" +
                "11066=File verification failed\r\n" +
                "11068=Game startup failed; winhttp.dll missing\r\n" +
                "11071=All URLs are invalid\r\n" +
                "12001=File missing; check game integrity or reinstall\r\n" +
                "12002=Incorrect file; check game integrity or reinstall\r\n" +
                "14001=File missing; check game integrity or reinstall\r\n" +
                "14002=Failed to parse file\r\n" +
                "14003=Failed to parse file\r\n" +
                "14004=Failed to parse file\r\n" +
                "15000=Active defense failed\r\n" +
                "15201=Active defense failed\r\n" +
                "15217=Active defense failed\r\n" +
                "15227=Multiple clients are running\r\n" +
                "15228=Please restart computer\r\n";
            File.WriteAllText(Path.Combine(avitalPicDir, "ErrConfig.ini"), errConfig, Encoding.Default);
            Log("Prepared local game config files");
        }
        catch (Exception ex)
        {
            Log("Preparing game config failed: " + ex.Message);
            throw;
        }
    }

    private void UpdateLoginFileList()
    {
        string listPath = Path.Combine(gameDir, "lloginfilelist.txt");
        if (!File.Exists(listPath))
        {
            return;
        }

        string paramPath = Path.Combine(gameDir, "param.ini");
        byte[] paramBytes = File.ReadAllBytes(paramPath);
        string paramLine = "param.ini|" + paramBytes.Length.ToString() + "|" + Md5Hex(paramBytes) + "|0100010045";
        string[] lines = File.ReadAllLines(listPath, Encoding.Default);
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].StartsWith("0100010045|", StringComparison.OrdinalIgnoreCase))
            {
                lines[i] = "0100010045|http://127.0.0.1:18090/loginupdater/";
            }
            else if (lines[i].StartsWith("param.ini|", StringComparison.OrdinalIgnoreCase))
            {
                lines[i] = paramLine;
            }
        }
        File.WriteAllLines(listPath, lines, Encoding.Default);
    }

    private static string Md5Hex(byte[] data)
    {
        using (MD5 md5 = MD5.Create())
        {
            byte[] hash = md5.ComputeHash(data);
            StringBuilder builder = new StringBuilder(hash.Length * 2);
            foreach (byte item in hash)
            {
                builder.Append(item.ToString("x2"));
            }
            return builder.ToString();
        }
    }

    private void StopLocalServices()
    {
        if (localProcess == null || localProcess.HasExited)
        {
            Log("No owned local services are running");
            return;
        }
        Log("Stopping owned local services");
        KillTree(localProcess.Id);
    }

    private void StopOwnedLocalProcess()
    {
        try
        {
            if (localProcess != null && !localProcess.HasExited)
            {
                KillTree(localProcess.Id);
            }
        }
        catch
        {
        }
    }

    private static void KillTree(int pid)
    {
        string taskkill = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "taskkill.exe");
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = taskkill;
        psi.Arguments = "/F /T /PID " + pid.ToString();
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process proc = Process.Start(psi);
        if (proc != null)
        {
            proc.WaitForExit(5000);
        }
    }

    private List<string> GetBusyLocalPorts()
    {
        List<string> busy = new List<string>();
        int[] ports = new int[] { 18090, 15000, 9000, 9024 };
        foreach (int port in ports)
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                listener.Start();
            }
            catch
            {
                string owner = GetPortOwnerPid(port);
                busy.Add(owner.Length == 0 ? port.ToString() : port.ToString() + " (pid " + owner + ")");
            }
            finally
            {
                if (listener != null)
                {
                    listener.Stop();
                }
            }
        }
        return busy;
    }

    private static string GetPortOwnerPid(int port)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "netstat.exe";
            psi.Arguments = "-ano -p tcp";
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.CreateNoWindow = true;
            Process proc = Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            string needle = "127.0.0.1:" + port.ToString();
            string[] lines = output.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                if (line.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0 &&
                    line.IndexOf("LISTENING", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string[] parts = Regex.Split(line.Trim(), @"\s+");
                    if (parts.Length > 0)
                    {
                        return parts[parts.Length - 1];
                    }
                }
            }
        }
        catch
        {
        }
        return "";
    }

    private void StartRemoteServer()
    {
        try
        {
            if (!AssertGameExists())
            {
                return;
            }
            string host;
            int port;
            ParseHostPort(remoteServerBox.Text, out host, out port);
            string account = remoteAccountBox.Text.Trim();
            if (account.Length == 0)
            {
                throw new InvalidOperationException("Account is required");
            }
            string password = remotePasswordBox.Text;
            Log("Requesting developer-server auth: " + host + ":" + port.ToString());
            TicketResult result = RequestRemoteTicket(host, port, account, password);
            Log(result.Note);
            LaunchGame(BuildGameArgs(account, result.Ticket, host, port.ToString()));
        }
        catch (Exception ex)
        {
            Log("Remote login failed: " + ex.Message);
            MessageBox.Show(ex.Message, "Remote login failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static void ParseHostPort(string text, out string host, out int port)
    {
        string value = (text ?? "").Replace('\uff1a', ':').Trim();
        if (value.Length == 0)
        {
            host = "127.0.0.1";
            port = 15000;
            return;
        }
        int index = value.LastIndexOf(':');
        if (index < 0)
        {
            host = value;
            port = 15000;
            return;
        }
        host = value.Substring(0, index).Trim();
        if (host.Length == 0)
        {
            host = "127.0.0.1";
        }
        string portText = value.Substring(index + 1).Trim();
        if (!Int32.TryParse(portText, out port) || port < 1 || port > 65535)
        {
            throw new InvalidOperationException("Port is not a valid number in range: " + portText);
        }
    }

    private TicketResult RequestRemoteTicket(string host, int proxyPort, string account, string password)
    {
        string body = "{\"username\":\"" + JsonEscape(account) + "\",\"account\":\"" + JsonEscape(account) + "\",\"password\":\"" + JsonEscape(password) + "\"}";
        List<string> urls = new List<string>();
        urls.Add("http://" + host + ":18090/auth/login");
        urls.Add("http://" + host + ":18090/login");
        if (proxyPort != 18090)
        {
            urls.Add("http://" + host + ":" + proxyPort.ToString() + "/auth/login");
            urls.Add("http://" + host + ":" + proxyPort.ToString() + "/login");
        }

        string lastError = "";
        foreach (string url in urls)
        {
            try
            {
                string response = PostJson(url, body);
                string ticket = FindTicket(response);
                if (ticket.Length > 0)
                {
                    return new TicketResult(ticket, "Auth succeeded: " + url);
                }
                lastError = url + " did not return auth_ticket/ticket/token";
            }
            catch (Exception ex)
            {
                lastError = url + " " + ex.Message;
            }
        }

        if (!String.IsNullOrWhiteSpace(password))
        {
            return new TicketResult(password.Trim(), "No HTTP ticket was returned; using the password/ticket field as -login. Last error: " + lastError);
        }
        throw new InvalidOperationException("Could not obtain an auth ticket. Last error: " + lastError);
    }

    private static string PostJson(string url, string body)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(body);
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.Method = "POST";
        request.ContentType = "application/json";
        request.UserAgent = "FinalCombatLocalLauncher/1.0";
        request.Timeout = 4000;
        request.ReadWriteTimeout = 4000;
        request.ContentLength = bytes.Length;
        using (Stream stream = request.GetRequestStream())
        {
            stream.Write(bytes, 0, bytes.Length);
        }
        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        using (Stream stream = response.GetResponseStream())
        using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
        {
            return reader.ReadToEnd();
        }
    }

    private static string FindTicket(string json)
    {
        string[] keys = new string[] { "auth_ticket", "ticket", "login", "token" };
        foreach (string key in keys)
        {
            Match match = Regex.Match(json, "\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
            if (match.Success)
            {
                return Regex.Unescape(match.Groups[1].Value);
            }
        }
        return "";
    }

    private static string JsonEscape(string value)
    {
        if (value == null)
        {
            return "";
        }
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    private static string JoinArgs(string[] args)
    {
        List<string> quoted = new List<string>();
        foreach (string arg in args)
        {
            quoted.Add(QuoteArg(arg));
        }
        return String.Join(" ", quoted.ToArray());
    }

    private static string QuoteArg(string arg)
    {
        if (arg == null)
        {
            return "\"\"";
        }
        if (arg.Length == 0 || arg.IndexOfAny(new char[] { ' ', '\t', '"' }) >= 0)
        {
            return "\"" + arg.Replace("\"", "\\\"") + "\"";
        }
        return arg;
    }

    private sealed class TicketResult
    {
        public readonly string Ticket;
        public readonly string Note;

        public TicketResult(string ticket, string note)
        {
            Ticket = ticket;
            Note = note;
        }
    }
}
