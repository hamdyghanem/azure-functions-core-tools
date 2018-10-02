using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Azure.Functions.Cli.Interfaces;
using Colors.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static Colors.Net.StringStaticMethods;

namespace Azure.Functions.Cli.Common
{
    internal class AuthManager : IAuthManager
    {
        private readonly ISecretsManager _secretsManager;
        private const string requiredResources = "requiredresources.json";

        public AuthManager(ISecretsManager secretsManager)
        {
            _secretsManager = secretsManager;
            var connectionString = secretsManager.GetSecrets().FirstOrDefault(s => s.Key.Equals("AzureWebJobsStorage", StringComparison.OrdinalIgnoreCase)).Value;
        }

        public async Task CreateAADApplication(string accessToken, string appName)
        {
            if (string.IsNullOrEmpty(appName))
            {
                throw new CliArgumentsException("Must specify name of new Azure Active Directory application with --app-name parameter.",
                    new CliArgument { Name = "app-name", Description = "Name of new Azure Active Directory application" });
            }

            if (CommandChecker.CommandExists("az"))
            {
                string homepage = "https://" + appName + ".azurewebsites.net";                            

                string authCallback = "/.auth/login/aad/callback";
                string replyUrl = homepage + authCallback;
                string localhostSSL = "https://localhost:7071" + authCallback; // TODO: think about variable port
                string localhost = "http://localhost:7071" + authCallback; // TODO: think about variable port
            
                var replyUrls = new List<string>
                {
                    replyUrl,
                    localhostSSL,
                    localhost
                };
                replyUrls.Sort();

                string serializedReplyUrls = string.Join(" ", replyUrls.ToArray<string>());

                string clientSecret = AzureActiveDirectoryClientLite.GeneratePassword(128);

                string query = $"--display-name {appName} --homepage {homepage} --identifier-uris {homepage} --password {clientSecret}" +
                    $" --reply-urls {serializedReplyUrls} --oauth2-allow-implicit-flow true";

                if (File.Exists(requiredResources))
                {
                    query += $" --required-resource-accesses @{requiredResources}";
                }
                else
                {
                    ColoredConsole.WriteLine($"Cannot find Required Resources file {requiredResources}. They will be missing from the AD application manifest.");
                }

                var az = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? new Executable("cmd", $"/c az ad app create {query}")
                    : new Executable("az", $"ad app create {query}");

                var stdout = new StringBuilder();
                var stderr = new StringBuilder();
                int exitCode = await az.RunAsync(o => stdout.AppendLine(o), e => stderr.AppendLine(e));
                var response = stdout.ToString().Trim(' ', '\n', '\r', '"');

                if (exitCode != 0)
                {
                    ColoredConsole.WriteLine(Red(stderr.ToString().Trim(' ', '\n', '\r', '"')));
                    return;
                }

                // Update function application's (local) auth settings
                JObject application = JObject.Parse(response);
                var jwt = new JwtSecurityToken(accessToken);
                string tenantId = jwt.Payload["tid"] as string;
                CreateAuthSettings(appName, (string)application["appId"], clientSecret, tenantId, replyUrls);
                ColoredConsole.WriteLine(Green(response));             
            }
            else
            {
                throw new FileNotFoundException("Cannot find az cli. `auth create-aad` requires the Azure CLI.");
            }
        }

        public void CreateAuthSettings(string appName, string clientId, string clientSecret, string tenant, List<string> replyUrls)
        {
            string homepage = "https://" + appName + ".azurewebsites.net";

            // The WEBSITE_AUTH_ALLOWED_AUDIENCES setting is of the form "{replyURL1} {replyURL2}", whereas
            // the 'allowedAudiences' setting of /config/authsettings is of the form ["{replyURL1}", "{replyURL2}"]
            string serializedArray = JsonConvert.SerializeObject(replyUrls, Formatting.Indented);
            string serializedReplyUrls = string.Join(" ", replyUrls.ToArray<string>());

            // 1. Create a local auth .json file to update the Site's auth settings via /config/authsettings
            var authSettingsFile = SecretsManager.AuthSettingsFileName;
            var authsettings = new AuthSettingsFile(authSettingsFile);
                
            authsettings.SetAuthSetting("allowedAudiences", serializedArray);
            authsettings.SetAuthSetting("isAadAutoProvisioned", "true");
            authsettings.SetAuthSetting("clientId", clientId);
            authsettings.SetAuthSetting("clientSecret", clientSecret);
            authsettings.SetAuthSetting("defaultProvider", "0"); // 0 corresponds to AzureActiveDirectory
            authsettings.SetAuthSetting("enabled", "True");
            authsettings.SetAuthSetting("issuer", "https://sts.windows.net/" + tenant + "/");
            authsettings.SetAuthSetting("runtimeVersion", "1.0.0");
            authsettings.SetAuthSetting("tokenStoreEnabled", "true");
            authsettings.SetAuthSetting("unauthenticatedClientAction", "1"); // Corresponds to AllowAnonymous

            authsettings.Commit();

            // 2. Create a local auth .json file that will be used by the middleware
            var middlewareAuthSettingsFile = SecretsManager.MiddlewareAuthSettingsFileName;
            var middlewareAuthsettings = new AuthSettingsFile(middlewareAuthSettingsFile);

            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_AUTO_AAD", "True");
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_CLIENT_ID", clientId);
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_CLIENT_SECRET", clientSecret);
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_DEFAULT_PROVIDER", "AzureActiveDirectory");
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_ENABLED", "True");
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_OPENID_ISSUER", "https://sts.windows.net/" + tenant + "/");
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_RUNTIME_VERSION", "1.0.0");
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_TOKEN_STORE", "true");
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_UNAUTHENTICATED_ACTION", "AllowAnonymous");

            // Middleware requires signing and encryption keys for local testing
            // These will be different than the encryption and signing keys used by the application in production
            string encryptionKey = ComputeSha256Hash(clientSecret);
            string signingKey = ComputeSha256Hash(clientId);      
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_ENCRYPTION_KEY", encryptionKey);
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_SIGNING_KEY", signingKey);
            middlewareAuthsettings.SetAuthSetting("WEBSITE_AUTH_ALLOWED_AUDIENCES", serializedReplyUrls);

            middlewareAuthsettings.Commit();
        }

        public async Task DeleteAADApplication(string id)
        {
            if (CommandChecker.CommandExists("az"))
            {
                string query = $"--id {id}";
                var az = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? new Executable("cmd", $"/c az ad app delete {query}")
                    : new Executable("az", $"ad app delete {query}");

                var stdout = new StringBuilder();
                var stderr = new StringBuilder();
                var exitCode = await az.RunAsync(o => stdout.AppendLine(o), e => stderr.AppendLine(e));
                if (exitCode != 0)
                {
                    throw new CliException(stderr.ToString().Trim(' ', '\n', '\r'));
                }
                else
                {
                    // Successful delete call does not return anything, so write success message
                    ColoredConsole.WriteLine(Green($"AAD Application {id} successfully deleted"));
                }
            }
            else
            {
                throw new FileNotFoundException("Cannot find az cli. `auth delete-aad` requires the Azure CLI.");
            }
        }

        static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}