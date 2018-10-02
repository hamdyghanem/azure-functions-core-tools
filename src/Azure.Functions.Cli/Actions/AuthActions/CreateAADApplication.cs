using System;
using System.Threading.Tasks;
using Azure.Functions.Cli.Common;
using Azure.Functions.Cli.Interfaces;
using Fclp;

namespace Azure.Functions.Cli.Actions.AuthActions
{
    // Access via `func auth create-aad --app-name {displayName}`
    [Action(Name = "create-aad", Context = Context.Auth, HelpText = "Creates an Azure Active Directory application with given application name")]
    class CreateAADApplication : BaseAuthAction
    {
        private readonly IAuthManager _authManager;

        public string AppName { get; set; }

        public CreateAADApplication(IAuthManager authManager)
        {
            _authManager = authManager;
        }
        
        public override async Task RunAsync()
        {
            await _authManager.CreateAADApplication(AccessToken, AppName);
        }

        public override ICommandLineParserResult ParseArgs(string[] args)
        {
            Parser
                .Setup<string>("app-name")
                .WithDescription("Name of AD application to create")
                .Callback(f => AppName = f);

            return base.ParseArgs(args);
        }
    }
}
