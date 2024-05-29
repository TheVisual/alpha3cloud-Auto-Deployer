using Newtonsoft.Json;
using nsoftware.async.IPWorksSSH;
using System.Net;
using System.Text;
using System.Text.Json;
using Zennolab.CapMonsterCloud;
using Zennolab.CapMonsterCloud.Requests;

public static class MethodsExensions
{
    private static readonly object fileWriteLock = new object();

	public static async Task<string> SolveCaptchaSJC()
	{

		var clientOptions = new ClientOptions
		{
			ClientKey = File.ReadAllText("capmonsterkey.txt"),
		};
		var cmCloudClient = CapMonsterCloudClientFactory.Create(clientOptions);
		var recaptchaV3Request = new RecaptchaV3ProxylessRequest
		{
			WebsiteUrl = "https://sjc.alpha3cloud.com/",
			WebsiteKey = "6LeISb4aAAAAAH4ZntJICkE0jWp8RrbuYLMsQ70N",
			MinScore = 0.3
		};

		var recaptchaV3Result = await cmCloudClient.SolveAsync(recaptchaV3Request);
		var solution = recaptchaV3Result.Solution.Value;

		if (solution != null)
		{
			return solution;
		}
		else
		{
			throw new FailedCaptcha();
		}
	}

    public static async Task<string> SolveCaptchaWDC()
    {

        var clientOptions = new ClientOptions
        {
            ClientKey = File.ReadAllText("capmonsterkey.txt"),
        };
        var cmCloudClient = CapMonsterCloudClientFactory.Create(clientOptions);
        var recaptchaV3Request = new RecaptchaV3ProxylessRequest
        {
            WebsiteUrl = "https://wdc.alpha3cloud.com/",
            WebsiteKey = "6LeISb4aAAAAAH4ZntJICkE0jWp8RrbuYLMsQ70N",
            MinScore = 0.3
        };

        var recaptchaV3Result = await cmCloudClient.SolveAsync(recaptchaV3Request);
        var solution = recaptchaV3Result.Solution.Value;

        if (solution != null)
        {
            return solution;
        }
        else
        {
            throw new FailedCaptcha();
        }
    }

    public class gcaptcha
    {
        [JsonProperty("g-recaptcha-response")]
        public string grecaptcharesponse { get; set; }
    }

    public class Hacky
    {
        public bool success { get; set; }
        public string uuid { get; set; }
    }


    public class CloneEndpoint
    {
        [JsonProperty("size")]
        public long size { get; set; }
    }
    public class Drife
    {
        public int boot_order { get; set; }
        public string dev_channel { get; set; }
        public string device { get; set; }
        public Drive drive { get; set; }
        public object runtime { get; set; }
    }

    public class Drive
    {
        public string resource_uri { get; set; }
        public string uuid { get; set; }
    }
    public class Io
    {
        public int bytes_recv { get; set; }
        public int bytes_sent { get; set; }
        public int packets_recv { get; set; }
        public int packets_sent { get; set; }
    }
    public class IpV4Conf
    {
        public string conf { get; set; }
        public string ip { get; set; }
    }
    public class IpV4
    {
        public string resource_uri { get; set; }
        public string uuid { get; set; }
    }

    public class Meta
    {

    }

    public class Runtime2
    {
        public string interface_type { get; set; }
        public Io io { get; set; }
        public IpV4 ip_v4 { get; set; }
        public object ip_v6 { get; set; }
        public int rx_foreign { get; set; }
        public int rx_local { get; set; }
        public int tx_foreign { get; set; }
        public int tx_local { get; set; }
    }

    public class Nic
    {
        public object boot_order { get; set; }
        public object firewall_policy { get; set; }
        public IpV4Conf ip_v4_conf { get; set; }
        public object ip_v6_conf { get; set; }
        public string mac { get; set; }
        public string model { get; set; }
        public Runtime2 runtime { get; set; }
        public object vlan { get; set; }
    }

    public class Owner
    {
        public string resource_uri { get; set; }
        public string uuid { get; set; }
    }

    public class StartJSon
    {
        public List<Object> objects { get; set; }
    }

    public class ServersJson
    {
        public string name { get; set; }
        public string vnc_password { get; set; }
        public List<object> tags { get; set; }
        public List<Nic> nics { get; set; }
        public List<Drife> drives { get; set; }
        public string cpu_type { get; set; }
        public string hypervisor { get; set; }
        public int cpu { get; set; }
        public long mem { get; set; }
        public int smp { get; set; }
        public Meta meta { get; set; }
        public List<object> pubkeys { get; set; }
    }

    public class Job
    {
        public string resource_uri { get; set; }
        public string uuid { get; set; }
    }
    public class Object
    {
        public object allocation_pool { get; set; }
        public bool auto_start { get; set; }
        public bool context { get; set; }
        public int cpu { get; set; }
        public object cpu_model { get; set; }
        public string cpu_type { get; set; }
        public bool cpus_instead_of_cores { get; set; }
        public List<Drife> drives { get; set; }
        public bool enable_numa { get; set; }
        public List<object> epcs { get; set; }
        public List<object> gpus { get; set; }
        public List<object> grantees { get; set; }
        public bool hv_relaxed { get; set; }
        public bool hv_tsc { get; set; }
        public string hypervisor { get; set; }
        public bool is_grey { get; set; }
        public List<object> jobs { get; set; }
        public long mem { get; set; }
        public Meta meta { get; set; }
        public string name { get; set; }
        public List<Nic> nics { get; set; }
        public Owner owner { get; set; }
        public List<object> permissions { get; set; }
        public List<object> pubkeys { get; set; }
        public List<object> requirements { get; set; }
        public string resource_uri { get; set; }
        public object runtime { get; set; }
        public int smp { get; set; }
        public string status { get; set; }
        public List<object> tags { get; set; }
        public string uuid { get; set; }
        public string vnc_password { get; set; }
    }


    public class CloneJSonResponse
    {
        public List<Object> objects { get; set; }
    }

    public class Runtime
    {
        public bool is_snapshotable { get; set; }
        public int snapshots_allocated_size { get; set; }
        public string storage_type { get; set; }
    }


    public class Object2
    {
        public object allocation_pool { get; set; }
        public bool auto_start { get; set; }
        public bool context { get; set; }
        public int cpu { get; set; }
        public object cpu_model { get; set; }
        public string cpu_type { get; set; }
        public bool cpus_instead_of_cores { get; set; }
        public List<Drife> drives { get; set; }
        public bool enable_numa { get; set; }
        public List<object> epcs { get; set; }
        public List<object> gpus { get; set; }
        public List<object> grantees { get; set; }
        public bool hv_relaxed { get; set; }
        public bool hv_tsc { get; set; }
        public string hypervisor { get; set; }
        public bool is_grey { get; set; }
        public List<object> jobs { get; set; }
        public long mem { get; set; }
        public Meta meta { get; set; }
        public string name { get; set; }
        public List<Nic> nics { get; set; }
        public Owner owner { get; set; }
        public List<object> permissions { get; set; }
        public List<object> pubkeys { get; set; }
        public List<object> requirements { get; set; }
        public string resource_uri { get; set; }
        public object runtime { get; set; }
        public int smp { get; set; }
        public string status { get; set; }
        public List<object> tags { get; set; }
        public string uuid { get; set; }
        public string vnc_password { get; set; }
    }

    public class ServerJSonResponse
    {
        public List<Object2> objects { get; set; }
    }

    public class ServerGetJSon
    {
        public object allocation_pool { get; set; }
        public bool auto_start { get; set; }
        public bool context { get; set; }
        public int cpu { get; set; }
        public object cpu_model { get; set; }
        public string cpu_type { get; set; }
        public bool cpus_instead_of_cores { get; set; }
        public List<Drife> drives { get; set; }
        public bool enable_numa { get; set; }
        public List<object> epcs { get; set; }
        public List<object> gpus { get; set; }
        public List<object> grantees { get; set; }
        public bool hv_relaxed { get; set; }
        public bool hv_tsc { get; set; }
        public string hypervisor { get; set; }
        public bool is_grey { get; set; }
        public List<object> jobs { get; set; }
        public long mem { get; set; }
        public Meta meta { get; set; }
        public string name { get; set; }
        public List<Nic> nics { get; set; }
        public Owner owner { get; set; }
        public List<object> permissions { get; set; }
        public List<object> pubkeys { get; set; }
        public List<object> requirements { get; set; }
        public string resource_uri { get; set; }
        public Runtime runtime { get; set; }
        public int smp { get; set; }
        public string status { get; set; }
        public List<object> tags { get; set; }
        public string uuid { get; set; }
        public string vnc_password { get; set; }
    }
    private static string GetCsrfTokenFromCookies(CookieContainer cookieContainer)
    {
        Uri uri = new Uri("https://sjc.alpha3cloud.com"); // Replace with the appropriate domain you are dealing with
        CookieCollection cookies = cookieContainer.GetCookies(uri);

        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == "csrftoken") // Replace "csrftoken" with the actual name of the csrf token cookie
            {
                return cookie.Value;
            }
        }

        // Return null or an empty string if the csrf token is not found
        return null;
    }
            
    public static async Task DeploySSHSJC(string capKey)
    {
        CookieContainer cookieContainer = new CookieContainer();
        var VNC_PASSWORD = RandomExtensions.NextString(new Random(), 8);
        using (HttpClient httpClient = new HttpClient(new HttpClientHandler { CookieContainer = cookieContainer, AutomaticDecompression = DecompressionMethods.All, Proxy = new WebProxy() })) // Put Proxy Here
		{
            // Set request headers
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
            httpClient.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate, br");
            httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
            httpClient.DefaultRequestHeaders.Add("Dnt", "1");
            httpClient.DefaultRequestHeaders.Add("Origin", "https://sjc.alpha3cloud.com");
            httpClient.DefaultRequestHeaders.Add("Referer", "https://sjc.alpha3cloud.com/ui/4.0/login");
            httpClient.DefaultRequestHeaders.Add("Sec-Ch-Ua", "\"Not/A)Brand\";v=\"8\", \"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\"");
            httpClient.DefaultRequestHeaders.Add("Sec-Ch-Ua-Mobile", "?0");
            httpClient.DefaultRequestHeaders.Add("Sec-Ch-Ua-Platform", "\"Windows\"");
            httpClient.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "empty");
            httpClient.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "cors");
            httpClient.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");
            httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

            // Create the JSON payload
            string payloadJson = JsonConvert.SerializeObject(new gcaptcha { grecaptcharesponse = capKey });

            // Create the StringContent object with JSON payload and set the content type
            StringContent content = new StringContent(payloadJson, Encoding.UTF8, "application/json");

            // Make the POST request
            HttpResponseMessage response = await httpClient.PostAsync("https://sjc.alpha3cloud.com/api/2.0/accounts/action/?do=get_guest_user", content);

            // Check if the request was successful (status code in the range of 200-299)
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Trial Started");
                // Read the response content as a string
                string responseContent = await response.Content.ReadAsStringAsync();

                using (HttpClient httpClientClone = new HttpClient(new HttpClientHandler { CookieContainer = cookieContainer, AutomaticDecompression = DecompressionMethods.All, Proxy = new WebProxy() })) // Put Proxy Here
				{
                    httpClientClone.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
                    httpClientClone.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate, br");
                    httpClientClone.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7");;
                    httpClientClone.DefaultRequestHeaders.Add("Origin", "https://sjc.alpha3cloud.com");
                    httpClientClone.DefaultRequestHeaders.Add("Referer", "https://sjc.alpha3cloud.com/ui/4.0/servers_kvm/simplecreation");
                    httpClientClone.DefaultRequestHeaders.Add("Sec-Ch-Ua", "\"Not/A)Brand\";v=\"8\", \"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\"");
                    httpClientClone.DefaultRequestHeaders.Add("Sec-Ch-Ua-Mobile", "?0");
                    httpClientClone.DefaultRequestHeaders.Add("Sec-Ch-Ua-Platform", "\"Windows\"");
                    httpClientClone.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "empty");
                    httpClientClone.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "cors");
                    httpClientClone.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");
                    httpClientClone.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                    // After making the HTTP request and storing cookies in the CookieContainer

                    // Now, you have the csrf token value and can use it in subsequent requests.
                    if (GetCsrfTokenFromCookies(cookieContainer) != null)
                    {
                        // Use the csrf token in your HTTP requests where required.
                        httpClientClone.DefaultRequestHeaders.Add("X-Csrftoken", GetCsrfTokenFromCookies(cookieContainer));
                    }

                    try
                    {
                        string payloadCloneJson = JsonConvert.SerializeObject(new CloneEndpoint { size = 53687091200 });
                        StringContent Clonecontent = new StringContent(payloadCloneJson, Encoding.UTF8, "application/json");
                        //HttpResponseMessage CreateVPS = await httpClientClone.PostAsync("https://sjc.alpha3cloud.com/api/2.0/drives/37ca751f-eee5-4c29-a9ef-31249d661742/action/?do=clone", Clonecontent);
                        HttpResponseMessage CreateVPS = await httpClientClone.PostAsync("https://sjc.alpha3cloud.com/api/2.0/drives/848b93ea-b92d-4291-a5d2-b4052ef0e81a/action/?do=clone", Clonecontent);
                        CreateVPS.EnsureSuccessStatusCode();
                        string responseBodyVPS = await CreateVPS.Content.ReadAsStringAsync();
                        var CloneJSon = JsonConvert.DeserializeObject<CloneJSonResponse>(responseBodyVPS);
                        Console.WriteLine("VPS Cloned");
                        using (HttpClient httpClientServer = new HttpClient(new HttpClientHandler { CookieContainer = cookieContainer, AutomaticDecompression = DecompressionMethods.All, Proxy = new WebProxy() })) // Put Proxy Here
						{
                            httpClientServer.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
                            httpClientServer.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate, br");
                            httpClientServer.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7"); ;
                            httpClientServer.DefaultRequestHeaders.Add("Origin", "https://sjc.alpha3cloud.com");
                            httpClientServer.DefaultRequestHeaders.Add("Referer", "https://sjc.alpha3cloud.com/ui/4.0/servers_kvm/simplecreation");
                            httpClientServer.DefaultRequestHeaders.Add("Sec-Ch-Ua", "\"Not/A)Brand\";v=\"8\", \"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\"");
                            httpClientServer.DefaultRequestHeaders.Add("Sec-Ch-Ua-Mobile", "?0");
                            httpClientServer.DefaultRequestHeaders.Add("Sec-Ch-Ua-Platform", "\"Windows\"");
                            httpClientServer.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "empty");
                            httpClientServer.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "cors");
                            httpClientServer.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");
                            httpClientServer.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                            // After making the HTTP request and storing cookies in the CookieContainer
                            // Now, you have the csrf token value and can use it in subsequent requests.
                            if (GetCsrfTokenFromCookies(cookieContainer) != null)
                            {
                                // Use the csrf token in your HTTP requests where required.
                                httpClientServer.DefaultRequestHeaders.Add("X-Csrftoken", GetCsrfTokenFromCookies(cookieContainer));
                            }

                            try
                            {
                                string payloadServer = JsonConvert.SerializeObject(new ServersJson
                                {
                                    name = "",
                                    vnc_password = "9C!EmQdW",
                                    tags = new List<object>(),
                                    nics = new List<Nic>
                                    {
                                        new Nic
                                        {
                                            model = "virtio",
                                            ip_v4_conf = new IpV4Conf
                                            {
                                                conf = "dhcp"
                                            }
                                        }
                                    },
                                    drives = new List<Drife>
                                    {
                                        new Drife
                                        {
                                            device = "virtio",
                                            drive = new Drive
                                            {
                                              resource_uri = CloneJSon.objects != null && CloneJSon.objects.Count > 0 ? CloneJSon.objects[0]?.resource_uri : null,
                                              uuid = CloneJSon.objects != null && CloneJSon.objects.Count > 0 ? CloneJSon.objects[0]?.uuid : null
                                            },
                                            dev_channel = "0:0",
                                            boot_order = 1
                                        }
                                    },
                                    cpu_type = "intel",
                                    hypervisor = "kvm",
                                    cpu = 3100,
                                    mem = 2147483648,
                                    smp = 1,
                                    meta = new Meta(),
                                    pubkeys = new List<object>()
                                });

                                Console.WriteLine(payloadServer);
                                StringContent Servercontent = new StringContent(payloadServer, Encoding.UTF8, "application/json");
                                HttpResponseMessage CreateServer = await httpClientServer.PostAsync("https://sjc.alpha3cloud.com/api/2.0/servers/", Servercontent);
                                CreateServer.EnsureSuccessStatusCode();
                                string responseBodyServer = await CreateServer.Content.ReadAsStringAsync();
                                var ServerJSon = JsonConvert.DeserializeObject<ServerJSonResponse>(responseBodyServer);
                                Console.WriteLine("VPS Created");
                                using (HttpClient httpClientStart = new HttpClient(new HttpClientHandler { CookieContainer = cookieContainer, AutomaticDecompression = DecompressionMethods.All, Proxy = new WebProxy() })) // Put Proxy Here
								{
                                    httpClientStart.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
                                    httpClientStart.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate, br");
                                    httpClientStart.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7"); ;
                                    httpClientStart.DefaultRequestHeaders.Add("Origin", "https://sjc.alpha3cloud.com");
                                    httpClientStart.DefaultRequestHeaders.Add("Referer", "https://sjc.alpha3cloud.com/ui/4.0/servers_kvm/simplecreation");
                                    httpClientStart.DefaultRequestHeaders.Add("Sec-Ch-Ua", "\"Not/A)Brand\";v=\"8\", \"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\"");
                                    httpClientStart.DefaultRequestHeaders.Add("Sec-Ch-Ua-Mobile", "?0");
                                    httpClientStart.DefaultRequestHeaders.Add("Sec-Ch-Ua-Platform", "\"Windows\"");
                                    httpClientStart.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "empty");
                                    httpClientStart.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "cors");
                                    httpClientStart.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");
                                    httpClientStart.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                                    // After making the HTTP request and storing cookies in the CookieContainer
                                    // Now, you have the csrf token value and can use it in subsequent requests.
                                    if (GetCsrfTokenFromCookies(cookieContainer) != null)
                                    {
                                        // Use the csrf token in your HTTP requests where required.
                                        httpClientStart.DefaultRequestHeaders.Add("X-Csrftoken", GetCsrfTokenFromCookies(cookieContainer));
                                    }

                                    try
                                    {
                                        string payloadstart = JsonConvert.SerializeObject(new StartJSon
                                        {
                                            objects = new List<Object>
                                            {
                                                new Object
                                                {
                                                    allocation_pool = null,
                                                    auto_start = false,
                                                    context = true,
                                                    cpu = 3100,
                                                    cpu_model = null,
                                                    cpu_type = "intel",
                                                    cpus_instead_of_cores = false,
                                                    drives = new List<Drife>
                                                    {
                                                        new Drife
                                                        {
                                                            boot_order = 1,
                                                            dev_channel = "0:0",
                                                            device = "virtio",
                                                            drive = new Drive
                                                            {
                                                                 resource_uri = ServerJSon.objects != null && ServerJSon.objects.Count > 0 ? ServerJSon.objects[0]?.drives.FirstOrDefault().drive.resource_uri : null,
                                                                 uuid = ServerJSon.objects != null && ServerJSon.objects.Count > 0 ? ServerJSon.objects[0]?.drives.FirstOrDefault().drive.uuid : null
                                                            },
                                                            runtime = null
                                                        }
                                                    },
                                                    enable_numa = false,
                                                    epcs = new List<object>(),
                                                    gpus = new List<object>(),
                                                    grantees = new List<object>(),
                                                    hv_relaxed = false,
                                                    hv_tsc = false,
                                                    hypervisor = "kvm",
                                                    is_grey = false,
                                                    jobs = new List<object>(),
                                                    mem = 2147483648,
                                                    meta = new Meta(),
                                                    name = "",
                                                    nics = new List<Nic>
                                                    {
                                                        new Nic
                                                        {
                                                            boot_order = null,
                                                            firewall_policy = null,
                                                            ip_v4_conf = new IpV4Conf
                                                            {
                                                                conf = "dhcp",
                                                                ip = null
                                                            },
                                                            ip_v6_conf = null,
                                                            mac = ServerJSon.objects.FirstOrDefault().nics.FirstOrDefault().mac,
                                                            model = "virtio",
                                                            runtime = null,
                                                            vlan = null
                                                        }
                                                    },
                                                    owner = new Owner
                                                    {
                                                        resource_uri = ServerJSon.objects != null && ServerJSon.objects.Count > 0 ? ServerJSon.objects[0]?.owner.resource_uri : null,
                                                        uuid = ServerJSon.objects != null && ServerJSon.objects.Count > 0 ? ServerJSon.objects[0]?.owner.uuid : null
                                                    },
                                                    permissions = new List<object>(),
                                                    pubkeys = new List<object>(),
                                                    requirements = new List<object>(),
                                                    resource_uri = ServerJSon.objects[0].resource_uri,
                                                    runtime = null,
                                                    smp = 1,
                                                    status = "stopped",
                                                    tags = new List<object>(),
                                                    uuid = ServerJSon.objects[0].uuid,
                                                    vnc_password = ServerJSon.objects[0].vnc_password
                                                }
                                            }
                                        });
                                        Console.WriteLine(payloadstart.ToString());
                                        StringContent startcontent = new StringContent(payloadstart, Encoding.UTF8, "application/json");
                                        HttpResponseMessage startServer = await httpClientServer.PostAsync($"https://sjc.alpha3cloud.com/api/2.0/servers/{ServerJSon.objects[0].uuid}/action/?do=start", startcontent);
                                        startServer.EnsureSuccessStatusCode();
                                        string responseBodystart = await startServer.Content.ReadAsStringAsync();
                                        Console.WriteLine("Start Server");
                                        var IP = "";
                                        await Task.Delay(TimeSpan.FromSeconds(5));
                                        while (string.IsNullOrEmpty(IP))
                                        {
                                            using (HttpClient IpClient = new HttpClient(new HttpClientHandler { CookieContainer = cookieContainer, AutomaticDecompression = DecompressionMethods.All, Proxy = new WebProxy() })) // Put Proxy Here
                                            {
                                                var IPResponse = await IpClient.GetAsync($"https://sjc.alpha3cloud.com/api/2.0/servers/{ServerJSon.objects[0].uuid}/");
                                                var IPJson = JsonConvert.DeserializeObject<ServerGetJSon>(await IPResponse.Content.ReadAsStringAsync());


                                                try
                                                {
                                                    IP = IPJson?.nics[0].runtime.ip_v4.uuid;
                                                }
                                                catch (Exception)
                                                { }



                                                if (!string.IsNullOrEmpty(IP))
                                                {
                                                    Console.WriteLine("Waiting 2 Minutes Before Connecting to Host");

                                                    await Task.Delay(TimeSpan.FromMinutes(2));
                                                    Console.WriteLine(IP);
                                                    var sshell = new Sshell
                                                    {
														RuntimeLicense = "", // Get Your Own License
														SSHUser = "cloudsigma",
                                                        SSHPassword = "Cloud2024",
                                                    };
                                                    sshell.OnSSHServerAuthentication += (sender, e) =>
                                                    {
                                                        if (e.Fingerprint.Any())
                                                        {
                                                            e.Accept = true;
                                                        }
                                                        Console.WriteLine("SSHServerAuthentication event triggered");
                                                    };

                                                    sshell.OnConnected += (sender, e) =>
                                                    {
                                                        Console.WriteLine("Connected");
                                                    };
                                                    sshell.OnStdout += (sender, e) =>
                                                    {
                                                        Console.WriteLine(e.Text);
                                                    };
                                                    sshell.OnStderr += (sender, e) =>
                                                    {
                                                        Console.WriteLine(e.Text);
                                                    };
                                                    await sshell.SSHLogon(IP, 22);

                                                    await Task.Delay(5000);
                                                    await sshell.SendStdinText("Cloud2024\n");
                                                    await Task.Delay(5000);
                                                    await sshell.SendStdinText("iQzPfvmFHMwc\n");
                                                    await Task.Delay(5000);
                                                    await sshell.SendStdinText("iQzPfvmFHMwc\n");

                                                    await Task.Delay(5000);

                                                    var sshell2 = new Sshell
                                                    {
                                                        RuntimeLicense = "", // Get Your Own License
														SSHUser = "cloudsigma",
                                                        SSHPassword = "iQzPfvmFHMwc",
                                                    };
                                                    sshell2.OnSSHServerAuthentication += (sender, e) =>
                                                    {
                                                        if (e.Fingerprint.Any())
                                                        {
                                                            e.Accept = true;
                                                        }
                                                        Console.WriteLine("SSHServerAuthentication event triggered");
                                                    };

                                                    sshell2.OnConnected += (sender, e) =>
                                                    {
                                                        Console.WriteLine("Connected");
                                                    };
                                                    sshell2.OnStdout += (sender, e) =>
                                                    {
                                                        Console.WriteLine(e.Text);

                                                    };
                                                    await sshell2.SSHLogon(IP, 22);

                                                    await Task.Delay(5000);
                                                    await sshell2.SendCommand(""); // Your SSH command Here
                                                    Console.WriteLine($"{IP} Executed GG");
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    catch (HttpRequestException ex)
                                    {
                                        Console.WriteLine(ex.Message);
                                    }
                                }
                            }
                            catch (HttpRequestException ex)
                            {
                                Console.WriteLine($"HTTP request failed: {ex.Message}");
                            }
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"HTTP request failed: {ex.Message}");
                    }
                }
            }
            else
            {
                // Handle the error if the request was not successful
                string responseContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine("Error: " + response.StatusCode + responseContent);
            }
        }
    }
}