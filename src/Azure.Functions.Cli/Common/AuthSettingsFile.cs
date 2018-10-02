using Azure.Functions.Cli.Common;
using Colors.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Azure.Functions.Cli.Common
{
    class AuthSettingsFile
    {      
        public bool IsEncrypted { get; set; }

        public Dictionary<string, string> Values { get; set; } = new Dictionary<string, string>();

        private readonly string _filePath;

        private const string reason = "secrets.manager.auth";

        public AuthSettingsFile(string filePath)
        {
            _filePath = filePath;
            try
            {
                var content = FileSystemHelpers.ReadAllTextFromFile(_filePath);
                var authSettings = JObject.Parse(content);
                Values = authSettings.ToObject<Dictionary<string, string>>();                
            }
            catch
            {
                Values = new Dictionary<string, string>();
                IsEncrypted = false;
            }
        }

        public void SetAuthSetting(string name, string value)
        {          
            if (IsEncrypted)
            {
                Values[name] = Convert.ToBase64String(ProtectedData.Protect(Encoding.Default.GetBytes(value), reason));
            }
            else
            {
                Values[name] = value;
            };
        }

        public void RemoveSetting(string name)
        {
            if (Values.ContainsKey(name))
            {
                Values.Remove(name);
            }
        }

        public void Commit()
        {
            FileSystemHelpers.WriteAllTextToFile(_filePath, JsonConvert.SerializeObject(this.GetValues(), Formatting.Indented));
            ColoredConsole.WriteLine($"Wrote application's auth settings to {_filePath}");
        }

        public IDictionary<string, string> GetValues()
        {
            if (IsEncrypted)
            {
                try
                {
                    return Values.ToDictionary(k => k.Key, v => string.IsNullOrEmpty((string) v.Value) ? string.Empty : 
                        Encoding.Default.GetString(ProtectedData.Unprotect(Convert.FromBase64String((string) v.Value), reason)));
                }
                catch (Exception e)
                {
                    throw new CliException("Failed to decrypt settings.", e);
                }
            }
            else
            {
                return Values.ToDictionary(k => k.Key, v => (string) v.Value);
            }
        }
    }
}
