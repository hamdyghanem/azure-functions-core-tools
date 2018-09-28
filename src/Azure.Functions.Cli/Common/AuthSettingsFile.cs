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

        public Dictionary<string, object> Values { get; set; } = new Dictionary<string, object>();

        private readonly string _filePath;

        private const string reason = "secrets.manager.auth";

        public AuthSettingsFile(string filePath)
        {
            _filePath = filePath;
            try
            {
                var content = FileSystemHelpers.ReadAllTextFromFile(_filePath);
                var authSettings = JObject.Parse(content);
                Values = authSettings.ToObject<Dictionary<string, object>>(); 
                
                // Serialize each of the auth settings to allow for arrays
                foreach (var pair in Values)
                {
                    Values[pair.Key] = JsonConvert.SerializeObject(pair.Value);
                }
            }
            catch
            {
                Values = new Dictionary<string, object>();
                IsEncrypted = false;
            }
        }

        public void SetAuthSetting(string name, object value)
        {
            if (value.GetType() != typeof(string))
            {
                value = JsonConvert.SerializeObject(value);
            }

            if (IsEncrypted)
            {
                Values[name] = Convert.ToBase64String(ProtectedData.Protect(Encoding.Default.GetBytes((string) value), reason));
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
                    return Values.ToDictionary(k => k.Key, v => string.IsNullOrEmpty((string) v.Value) ? string.Empty : Encoding.Default.GetString(ProtectedData.Unprotect(Convert.FromBase64String((string) v.Value), reason)));
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
