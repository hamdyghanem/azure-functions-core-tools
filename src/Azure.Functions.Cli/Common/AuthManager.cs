using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
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

            //if (accessToken == null)
            //{
            //    throw new ArgumentNullException("AccessToken");
            //}

            //var az = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            //        ? new Executable("cmd", $"/c az account get-access-token --resource https://management.azure.com/")
            //        : new Executable("az", $" account get-access-token --resource https://management.azure.com/");

            //var stdout = new StringBuilder();
            //var stderr = new StringBuilder();
            //var exitCode = await az.RunAsync(o => stdout.AppendLine(o), e => stderr.AppendLine(e));
            //if (exitCode != 0)
            //{
            //    throw new CliException(stderr.ToString().Trim(' ', '\n', '\r'));
            //}
            //else
            //{
            //    var token = JObject.Parse(stdout.ToString().Trim(' ', '\n', '\r', '"'));
            //    accessToken = (string) token["accessToken"];
            //}

            //ColoredConsole.WriteLine(accessToken);

            // // Get necessary information from access token
            //var jwt = new JwtSecurityToken(accessToken);
            //string audience = null, tenantId = null;
            //Uri serviceRoot = null;
            //try
            //{
            //    audience = jwt.Payload.Aud[0];
            //}
            //catch (Exception e)
            //{
            //    ColoredConsole.WriteLine(Red($"Could not retrieve audience or tenant ID from access token.\nError: {e.ToString()}"));
            //}

            //try
            //{
            //    tenantId = jwt.Payload["tid"] as string;
            //    Uri servicePointUri = new Uri(audience);
            //    serviceRoot = new Uri(servicePointUri, tenantId);
            //}
            //catch (Exception e)
            //{
            //    ColoredConsole.WriteLine(Red($"Could not retrieve tenant ID from access token.\nError: {e.ToString()}"));
            //}


            //var aadClient = new AzureActiveDirectoryClientLite(serviceRoot, accessToken);

            //var app = aadClient.CreateApplication(appName, serviceRoot.AbsoluteUri);
            //if (app != null)
            //{
            //    ColoredConsole.WriteLine(Green($"Successfully created AAD Application {app.DisplayName}"));

            //    // Update function application's app settings
            //    string clientSecret = app.PasswordCredentials?.FirstOrDefault()?.Value;
            //    CreateAuthSettings(appName, app.AppId, clientSecret, tenantId);

            //    string application = JsonConvert.SerializeObject(app, Formatting.Indented);
            //    ColoredConsole.WriteLine(application);
            //}

            //await Task.CompletedTask;


            if (CommandChecker.CommandExists("az"))
            {
                ColoredConsole.WriteLine(Yellow("command exists?"));
                string homepage = "https://" + appName + ".azurewebsites.net";
                string replyUrl = homepage + "/.auth/login/aad/callback";

                string clientSecret = AzureActiveDirectoryClientLite.GeneratePassword(128);

                string query = $"--display-name {appName} --homepage {homepage} --identifier-uris {homepage} --password {clientSecret}" +
                    $" --reply-urls {replyUrl} --oauth2-allow-implicit-flow true";

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
                await az.RunAsync(o => stdout.AppendLine(o), e => stderr.AppendLine(e));
                var response = stdout.ToString().Trim(' ', '\n', '\r', '"');

                // Update function application's app settings
                JObject application = JObject.Parse(response);
                var jwt = new JwtSecurityToken(accessToken);
                string tenantId = jwt.Payload["tid"] as string;
                CreateAuthSettings(appName, (string)application["appId"], clientSecret, tenantId);

                ColoredConsole.WriteLine(Green(response));
            }
            else
            {
                throw new FileNotFoundException("Cannot find az cli. `auth create-aad` requires the Azure CLI.");
            }
        }

        public void CreateAuthSettings(string appName, string clientId, string clientSecret, string tenant)
        {
            var authSettingsFile = SecretsManager.AuthSettingsFileName;
            var authsettings = new AuthSettingsFile(authSettingsFile);

            string homepage = "https://" + appName + ".azurewebsites.net";
            string replyUrl = homepage + "/.auth/login/aad/callback";

            string[] replyUrls = new string[]
            {
                replyUrl
            };

            authsettings.SetAuthSetting("allowedAudiences", replyUrls);
            authsettings.SetAuthSetting("isAadAutoProvisioned", "true");
            authsettings.SetAuthSetting("clientId", clientId);
            authsettings.SetAuthSetting("clientSecret", clientSecret);
            authsettings.SetAuthSetting("defaultProvider", 0); // 0 corresponds to AzureActiveDirectory
            authsettings.SetAuthSetting("enabled", "True");
            authsettings.SetAuthSetting("issuer", "https://sts.windows.net/" + tenant + "/");
            authsettings.SetAuthSetting("runtimeVersion", "1.0.0");
            authsettings.SetAuthSetting("tokenStoreEnabled", "true");
            authsettings.SetAuthSetting("unauthenticatedClientAction", 1); // Corresponds to AllowAnonymous

            authsettings.Commit();
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
    }
}
