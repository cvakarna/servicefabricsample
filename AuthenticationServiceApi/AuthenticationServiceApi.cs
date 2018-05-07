using System;
using System.Collections.Generic;
using System.Fabric;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using ICommonInterface.Model;
using ICommonInterfacePkg;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.ServiceFabric.Services.Communication.AspNetCore;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.V2.FabricTransport.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;

namespace AuthenticationServiceApi
{
    /// <summary>
    /// The FabricRuntime creates an instance of this class for each service type instance. 
    /// </summary>
    internal sealed class AuthenticationServiceApi : StatelessService,ICommunication
    {
        private readonly string KeyVaultAddress = "keyvaultaddress";
        private readonly string ClientSecret = "";
        private readonly string ClientId = "";

        public object ServiceInterfaces { get; private set; }

        public AuthenticationServiceApi(StatelessServiceContext context)
            : base(context)
        { }

        public Task<string> CreateSubScribersAsync(string topicName)
        {
            throw new NotImplementedException();
        }

        public Task<string> OnRouteMessageaAsync(string message)
        {
            return Task.FromResult(message);
        }
        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public Task<string> ReadAsync(MessageWrapper message)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// the method that will be provided to the KeyVaultClient to get Access Token
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        private async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {

            var clientCredential = new ClientCredential(this.ClientId, this.ClientSecret);

            var authContext = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await authContext.AcquireTokenAsync(resource, clientCredential);
            if (result == null)
                throw new InvalidOperationException("Failed to Obtain the Token");
            return result.AccessToken;
        }

        private async Task<string> GetConnectionStringAsync(string tenantName,string tenantId)
        {
            var kv = new KeyVaultClient(GetAccessTokenAsync, new HttpClient());
            var connectionString = kv.GetSecretAsync(this.KeyVaultAddress, tenantName).GetAwaiter().GetResult();
            var encryptedString = connectionString.Value;
            return encryptedString;
        }

        private async Task CreateKey()
        {
            var kv = new KeyVaultClient(GetAccessTokenAsync, new HttpClient());
            kv.CreateKeyAsync(this.KeyVaultAddress, "Siva", "");
        }

        /// <summary>
        /// Optional override to create listeners (like tcp, http) for this service instance.
        /// </summary>
        /// <returns>The collection of listeners.</returns>
        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return new ServiceInstanceListener[]
            {
                new ServiceInstanceListener(serviceContext =>
                    new KestrelCommunicationListener(serviceContext, "httpServiceEndpoint", (url, listener) =>
                    {
                        ServiceEventSource.Current.ServiceMessage(serviceContext, $"Starting Kestrel on {url}");

                        return new WebHostBuilder()
                                    .UseKestrel()
                                    .ConfigureServices(
                                        services => services
                                            .AddSingleton<StatelessServiceContext>(serviceContext))
                                    .UseContentRoot(Directory.GetCurrentDirectory())
                                    .UseStartup<Startup>()
                                    .UseServiceFabricIntegration(listener, ServiceFabricIntegrationOptions.None)
                                    .UseUrls(url)
                                    .Build();
                    }),name:"KestrelCommunicationListener"),

                  new ServiceInstanceListener((context) =>
                 {

                // return new FabricTransportServiceRemotingListener(context, this);

                return new FabricTransportServiceRemotingListener(context, this,new Microsoft.ServiceFabric.Services.Remoting.FabricTransport.Runtime.FabricTransportRemotingListenerSettings(){EndpointResourceName = "ServiceEndpointV2" });

               }, name: "RemotingListener"),

            };
        }

    }
}
