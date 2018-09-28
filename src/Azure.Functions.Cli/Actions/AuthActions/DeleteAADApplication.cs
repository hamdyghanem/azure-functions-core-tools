using System;
using System.Threading.Tasks;
using Azure.Functions.Cli.Common;
using Azure.Functions.Cli.Interfaces;
using Fclp;

namespace Azure.Functions.Cli.Actions.AuthActions
{
    // Access via `func auth create-aad {appName}`
    [Action(Name = "delete-aad", Context = Context.Auth, HelpText = "Creates an Azure Active Directory application with given application name")]
    class DeleteAADApplication : BaseAuthAction
    {
        private readonly IAuthManager _authManager;

        /// <summary>
        /// Identifier uri, application id, or object id
        /// </summary>
        public string Id { get; set; }

        public DeleteAADApplication(IAuthManager authManager)
        {
            _authManager = authManager;
        }

        public override async Task RunAsync()
        {
            await _authManager.DeleteAADApplication(Id);
        }

        public override ICommandLineParserResult ParseArgs(string[] args)
        {
            Parser
                .Setup<string>("id")
                .WithDescription("Identifier uri, application id, or object id of application to delete")
                .Callback(t => Id = t);

            return base.ParseArgs(args);
        }
    }
}
