using Colors.Net;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;

namespace Azure.Functions.Cli.Common
{
    /// <summary>
    /// Lightweight Azure AD graph API client implementation.
    /// </summary>
    /// <remarks>
    /// Only a small subset of graph API calls are supported by this lightweight client.
    /// A full-fledged client SDK is available from the AAD team, but this simplifies the
    /// dependency graph significantly
    /// </remarks>
    class AzureActiveDirectoryClientLite
    {
        Uri tenantUrl;
        string accessToken;

        public AzureActiveDirectoryClientLite(Uri tenantUrl, string accessToken)
        {
            this.tenantUrl = tenantUrl;
            this.accessToken = accessToken;
        }

        /// <summary>
        /// Creates an application in AAD and assigns it a new service principal.
        /// </summary>
        /// <param name="name">The display name of the application.</param>
        /// <param name="rootUri">The root URI of the application.</param>
        /// <param name="resourceAppId">The App ID of another application to which this app should be granted.</param>
        /// <returns>Returns the object ID of the created application.</returns>
        public Application CreateApplication(string name, string rootUri, string resourceAppId = null)
        {
            var app = new Application();
            app.DisplayName = name;
            app.Homepage = rootUri;
            app.IdentifierUris = new[] { rootUri };
            app.ReplyUrls = new[] { rootUri.TrimEnd('/') + "/.auth/login/aad/callback" };
            app.GroupMembershipClaims = "SecurityGroup";

            var passwordCredentials = new PasswordCredential[]
            {
                    new PasswordCredential { Value = GeneratePassword(128) },
            };

            app.PasswordCredentials = passwordCredentials;

            List<RequiredResourceAccess> accessPermissions = new List<RequiredResourceAccess>();

            // Set permissions for SSO and for Graph API access.
            var access = new RequiredResourceAccess();
            access.ResourceAppId = AADConstants.ServicePrincipals.AzureAdGraph;
            access.ResourceAccess = new ResourceAccess[]
            {
                    new ResourceAccess { Type = AADConstants.ResourceAccessTypes.User, Id = AADConstants.Permissions.EnableSSO },
                    new ResourceAccess { Type = AADConstants.ResourceAccessTypes.User, Id = AADConstants.Permissions.ReadDirectoryData },
            };

            accessPermissions.Add(access);

            if (resourceAppId != null)
            {
                // Set permissions for accessing other AAD applications.
                access = new RequiredResourceAccess();
                access.ResourceAppId = resourceAppId;
                access.ResourceAccess = new ResourceAccess[]
                {
                        new ResourceAccess { Type = AADConstants.ResourceAccessTypes.User, Id = AADConstants.Permissions.AccessApplication },
                };

                accessPermissions.Add(access);
            }

            app.RequiredResourceAccess = accessPermissions;

            string appJson = JsonSerializer.ToJson(app);

            ColoredConsole.WriteLine(string.Format("Creating application with name: {0} and URI: {1}", name, rootUri));

            // Request #1: Create the AAD application
            Application createdApp;
            using (WebResponse response = this.SendRequest("POST", "/applications", appJson))
            using (Stream connectStream = response.GetResponseStream())
            using (Stream stream = new MemoryStream())
            {
                connectStream.CopyTo(stream);
                stream.Position = 0;

                createdApp = JsonSerializer.FromJson<Application>(stream);
            }

            ColoredConsole.WriteLine(string.Format("Created application with AppId: {0} and ObjectId: {1}", createdApp.AppId, createdApp.ObjectId));

            // Request #2: Create the service principal for the AAD application
            var principal = new ServicePrincipal();
            principal.AccountEnabled = true;
            principal.AppId = createdApp.AppId;
            principal.DisplayName = app.DisplayName;

            // The first tag is required for the AAD app to show up properly in the legacy Azure portal.
            principal.Tags = new[] { "WindowsAzureActiveDirectoryIntegratedApp", "AppServiceIntegratedApp" };

            string servicePrincipalJson = JsonSerializer.ToJson(principal);
            this.SendRequest("POST", "/servicePrincipals", servicePrincipalJson).Close();

            createdApp.PasswordCredentials = passwordCredentials;
            return createdApp;
        }

        /// <summary>
        /// Deletes an AAD application.
        /// </summary>
        /// <param name="objectId">The object ID of the AAD application to delete.</param>
        public void DeleteApplication(string objectId)
        {
            this.DeleteObject(objectId, "Microsoft.DirectoryServices.Application");
        }

        internal void DeleteObject(string objectId, string objectType)
        {
            ColoredConsole.WriteLine(string.Format("Deleting object of type {0} and ID {1}.", objectType, objectId));
            string objectPath = string.Concat("/directoryObjects/", objectId, "/", objectType);
            this.SendRequest("DELETE", objectPath).Close();
            ColoredConsole.WriteLine(string.Format("Object of type {0} and ID {1} was successfully deleted.", objectType, objectId));
        }

        public WebResponse SendRequest(string method, string path, string jsonPayload = null)
        {
            var uriBuilder = new UriBuilder(this.tenantUrl);
            uriBuilder.Path = this.tenantUrl.AbsolutePath.TrimEnd('/') + path;
            uriBuilder.Query = "api-version=1.6";

            HttpWebRequest request = WebRequest.CreateHttp(uriBuilder.Uri);
            request.Method = method;
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + this.accessToken);

            if (!string.IsNullOrEmpty(jsonPayload))
            {
                request.ContentType = "application/json";
                using (var writer = new StreamWriter(request.GetRequestStream()))
                {
                    writer.Write(jsonPayload);
                }
            }

            ColoredConsole.WriteLine(String.Format("Sending request: {0} {1}", method, request.RequestUri));

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                ColoredConsole.WriteLine(string.Format("Request succeeded: {0}", (int)response.StatusCode));
                return response;
            }
            catch (WebException e)
            {
                if (e.Status == WebExceptionStatus.ProtocolError &&
                    e.Response != null &&
                    e.Response.ContentType != null &&
                    e.Response.ContentType.Contains("application/json"))
                {
                    using (var stream = e.Response.GetResponseStream())
                    {
                        ActiveDirectoryClientException aadException;
                        if (ActiveDirectoryClientException.TryCreate(stream, out aadException))
                        {
                            ColoredConsole.WriteLine(string.Format("Request failed: {0}", aadException.Message));
                            throw aadException;
                        }
                    }
                }

                throw;
            }

        }

        public static string GeneratePassword(int length)
        {
            const string PasswordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRSTWXYZ0123456789#$";
            string pwd = GetRandomString(PasswordChars, length);

            while (!MeetsConstraint(pwd))
            {
                pwd = GetRandomString(PasswordChars, length);
            }

            return pwd;
        }

        private static string GetRandomString(string allowedChars, int length)
        {
            StringBuilder retVal = new StringBuilder(length);
            byte[] randomBytes = new byte[length * 4];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);

                for (int i = 0; i < length; i++)
                {
                    int seed = BitConverter.ToInt32(randomBytes, i * 4);
                    Random random = new Random(seed);
                    retVal.Append(allowedChars[random.Next(allowedChars.Length)]);
                }
            }

            return retVal.ToString();
        }

        private static bool MeetsConstraint(string password)
        {
            return !string.IsNullOrEmpty(password) &&
                password.Any(c => char.IsUpper(c)) &&
                password.Any(c => char.IsLower(c)) &&
                password.Any(c => char.IsDigit(c)) &&
                password.Any(c => !char.IsLetterOrDigit(c));
        }

        static class AADConstants
        {
            public static class ServicePrincipals
            {
                public const string AzureAdGraph = "00000002-0000-0000-c000-000000000000";
            }

            public static class Permissions
            {
                public static readonly Guid AccessApplication = new Guid("92042086-4970-4f83-be1c-e9c8e2fab4c8");
                public static readonly Guid EnableSSO = new Guid("311a71cc-e848-46a1-bdf8-97ff7156d8e6");
                public static readonly Guid ReadDirectoryData = new Guid("5778995a-e1bf-45b8-affa-663a9f3f4d04");
                public static readonly Guid ReadAndWriteDirectoryData = new Guid("78c8a3c8-a07e-4b9e-af1b-b5ccab50a175");
            }

            public static class ResourceAccessTypes
            {
                public const string Application = "Role";
                public const string User = "Scope";
            }
        }

        /// <summary>
        /// Exception type that represents AAD graph API protocol errors.
        /// </summary>
        class ActiveDirectoryClientException : Exception
        {
            public ActiveDirectoryClientException(string message)
                : base(message)
            {
            }

            public static bool TryCreate(Stream stream, out ActiveDirectoryClientException e)
            {
                e = null;
                try
                {
                    ErrorPayload payload = JsonSerializer.FromJson<ErrorPayload>(stream);
                    if (payload != null && payload.Error != null && payload.Error.Message != null && payload.Error.Message.Value != null)
                    {
                        e = new ActiveDirectoryClientException(payload.Error.Message.Value);
                    }
                }
                catch (SerializationException)
                {
                    // swallow
                }

                return e != null;
            }

            [DataContract]
            class ErrorPayload
            {
                [DataMember(Name = "odata.error")]
                public ODataError Error { get; set; }
            }

            [DataContract]
            class ODataError
            {
                [DataMember(Name = "code")]
                public string Code { get; set; }

                [DataMember(Name = "message")]
                public ODataErrorMessage Message { get; set; }
            }

            [DataContract]
            class ODataErrorMessage
            {
                [DataMember(Name = "lang")]
                public string Language { get; set; }

                [DataMember(Name = "value")]
                public string Value { get; set; }
            }
        }
    }

    // See https://msdn.microsoft.com/Library/Azure/Ad/Graph/api/entity-and-complex-type-reference#ApplicationEntity
    [DataContract]
    class Application : IExtensibleDataObject
    {
        [DataMember(Name = "objectId", EmitDefaultValue = false)]
        public string ObjectId { get; set; }

        [DataMember(Name = "appId", EmitDefaultValue = false)]
        public string AppId { get; set; }

        [DataMember(Name = "availableToOtherTenants", EmitDefaultValue = false)]
        public bool? AvailableToOtherTenants { get; set; }

        [DataMember(Name = "displayName")]
        public string DisplayName { get; set; }

        [DataMember(Name = "groupMembershipClaims")]
        public string GroupMembershipClaims { get; set; }

        [DataMember(Name = "homepage")]
        public string Homepage { get; set; }

        [DataMember(Name = "identifierUris")]
        public IList<string> IdentifierUris { get; set; }

        [DataMember(Name = "passwordCredentials")]
        public IList<PasswordCredential> PasswordCredentials { get; set; }

        [DataMember(Name = "publicClient", EmitDefaultValue = false)]
        public bool? PublicClient { get; set; }

        [DataMember(Name = "replyUrls")]
        public IList<string> ReplyUrls { get; set; }

        [DataMember(Name = "requiredResourceAccess")]
        public IList<RequiredResourceAccess> RequiredResourceAccess { get; set; }

        ExtensionDataObject IExtensibleDataObject.ExtensionData { get; set; }
    }

    // See https://msdn.microsoft.com/Library/Azure/Ad/Graph/api/entity-and-complex-type-reference#RequiredResourceAccessType
    [DataContract]
    class RequiredResourceAccess
    {
        [DataMember(Name = "resourceAccess")]
        public IList<ResourceAccess> ResourceAccess { get; set; }

        [DataMember(Name = "resourceAppId")]
        public string ResourceAppId { get; set; }
    }

    // See https://msdn.microsoft.com/Library/Azure/Ad/Graph/api/entity-and-complex-type-reference#ResourceAccessType
    [DataContract]
    class ResourceAccess
    {
        [DataMember(Name = "id")]
        public Guid Id { get; set; }

        [DataMember(Name = "type")]
        public string Type { get; set; }
    }

    // See https://msdn.microsoft.com/Library/Azure/Ad/Graph/api/entity-and-complex-type-reference#ServicePrincipalEntity
    [DataContract]
    class ServicePrincipal
    {
        [DataMember(Name = "accountEnabled")]
        public bool AccountEnabled { get; set; }

        [DataMember(Name = "appId")]
        public string AppId { get; set; }

        [DataMember(Name = "displayName")]
        public string DisplayName { get; set; }

        [DataMember(Name = "tags")]
        public string[] Tags { get; set; }
    }

    [DataContract]
    class PasswordCredential
    {
        [DataMember(Name = "startDate")]
        string startDate;

        [DataMember(Name = "endDate")]
        string endDate;

        public PasswordCredential()
        {
            this.StartDate = DateTime.UtcNow;
            this.EndDate = this.StartDate.AddYears(1);
            this.KeyId = Guid.NewGuid();
        }

        [DataMember(Name = "keyId")]
        public Guid KeyId { get; set; }

        [DataMember(Name = "value")]
        public string Value { get; set; }

        public DateTime StartDate
        {
            get { return DateTime.Parse(this.startDate); }
            set { this.startDate = value.ToString("o"); }
        }

        public DateTime EndDate
        {
            get { return DateTime.Parse(this.endDate); }
            set { this.endDate = value.ToString("o"); }
        }
    }

    static class JsonSerializer
    {
        static readonly Dictionary<Type, DataContractJsonSerializer> Serializers = new Dictionary<Type, DataContractJsonSerializer>();

        public static string ToJson(object data)
        {
            DataContractJsonSerializer serializer = GetSerializer(data.GetType());
            using (var buffer = new MemoryStream())
            {
                serializer.WriteObject(buffer, data);
                return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
            }
        }

        public static T FromJson<T>(Stream jsonStream)
        {
            DataContractJsonSerializer serializer = GetSerializer(typeof(T));
            return (T)serializer.ReadObject(jsonStream);
        }

        static DataContractJsonSerializer GetSerializer(Type dataType)
        {
            DataContractJsonSerializer serializer;
            lock (Serializers)
            {
                if (!Serializers.TryGetValue(dataType, out serializer))
                {
                    serializer = new DataContractJsonSerializer(
                        dataType,
                        new DataContractJsonSerializerSettings
                        {
                            UseSimpleDictionaryFormat = true,
                            DateTimeFormat = new DateTimeFormat("o")
                        });
                    Serializers.Add(dataType, serializer);
                }
            }

            return serializer;
        }
    }
}
