// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Logging;
using Microsoft.Azure.WebJobs.Script.Description;
using Microsoft.Azure.WebJobs.Script.WebHost.Features;
using Microsoft.Azure.WebJobs.Script.WebHost.Security.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.WebJobs.Script.WebHost;
using Microsoft.Azure.AppService.Proxy.Common.Client;
using System.Linq;
using System.Reflection;

namespace Microsoft.Azure.WebJobs.Script.Host
{
    public class ProxyFunctionExecutor : IFuncExecutor
    {
        private readonly WebScriptHostManager _scriptHostManager;
        private readonly IWebJobsRouteHandler _routeHandler;

        internal ProxyFunctionExecutor(WebScriptHostManager scriptHostManager, IWebJobsRouteHandler routeHandler)
        {
            _scriptHostManager = scriptHostManager;
            _routeHandler = routeHandler;
        }

        public async Task ExecuteFuncAsync(string functionName, Dictionary<string, object> arguments, CancellationToken cancellationToken)
        {
            var request = arguments[ScriptConstants.AzureFunctionsHttpRequestKey] as HttpRequest;

            var route = request.HttpContext.GetRouteData();

            RouteContext rc = new RouteContext(request.HttpContext);

            foreach (var router in route.Routers)
            {
                var webJobsRouter = router as WebJobsRouter;
                if (webJobsRouter != null)
                {
                    var routeColection = typeof(WebJobsRouter).GetField("_routeCollection", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(webJobsRouter);
                    var routes = typeof(RouteCollection).GetField("_routes", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(routeColection) as List<IRouter>;

                    if (routes != null)
                    {
                        routes.Reverse();
                    }

                    await webJobsRouter.RouteAsync(rc);

                    if (rc.RouteData != null && rc.RouteData.DataTokens != null)
                    {
                        functionName = rc.RouteData.DataTokens["AZUREWEBJOBS_FUNCTIONNAME"].ToString();
                    }
                }
            }

            var context = request.HttpContext;
            var host = _scriptHostManager.Instance;

            var function = _scriptHostManager.Instance.Functions.FirstOrDefault(f => string.Equals(f.Name, functionName));

            context.Features.Set<IFunctionExecutionFeature>(new FunctionExecutionFeature(host, function));

            IFunctionExecutionFeature functionExecution = context.Features.Get<IFunctionExecutionFeature>();

            if (functionExecution != null && !context.Response.HasStarted)
            {
                IActionResult result = await GetResultAsync(context, functionExecution);

                var actionContext = new ActionContext
                {
                    HttpContext = context
                };

                await result.ExecuteResultAsync(actionContext);
            }

            //await _routeHandler.InvokeAsync(request.HttpContext, functionName);
        }

        private async Task<IActionResult> GetResultAsync(HttpContext context, IFunctionExecutionFeature functionExecution)
        {
            if (functionExecution.Descriptor == null)
            {
                return new NotFoundResult();
            }

            // Add route data to request info
            // TODO: Keeping this here for now as other code depend on this property, but this can be done in the HTTP binding.
            var routingFeature = context.Features.Get<IRoutingFeature>();
            context.Items.Add(HttpExtensionConstants.AzureWebJobsHttpRouteDataKey, new Dictionary<string, object>(routingFeature.RouteData.Values));

            bool authorized = await AuthenticateAndAuthorizeAsync(context, functionExecution.Descriptor);
            if (!authorized)
            {
                return new UnauthorizedResult();
            }

            // If the function is disabled, return 'NotFound', unless the request is being made with Admin credentials
            if (functionExecution.Descriptor.Metadata.IsDisabled &&
                !AuthUtility.PrincipalHasAuthLevelClaim(context.User, AuthorizationLevel.Admin))
            {
                return new NotFoundResult();
            }

            if (functionExecution.CanExecute)
            {
                // Add the request to the logging scope. This allows the App Insights logger to
                // record details about the request.
                ILoggerFactory loggerFactory = context.RequestServices.GetService<ILoggerFactory>();
                ILogger logger = loggerFactory.CreateLogger(LogCategories.CreateFunctionCategory(functionExecution.Descriptor.Name));
                var scopeState = new Dictionary<string, object>()
                {
                    [ScriptConstants.LoggerHttpRequest] = context.Request
                };

                using (logger.BeginScope(scopeState))
                {
                    // TODO: Flow cancellation token from caller
                    await functionExecution.ExecuteAsync(context.Request, CancellationToken.None);
                }
            }

            if (context.Items.TryGetValue(ScriptConstants.AzureFunctionsHttpResponseKey, out object result) && result is IActionResult actionResult)
            {
                return actionResult;
            }

            return new OkResult();
        }

        private async Task<bool> AuthenticateAndAuthorizeAsync(HttpContext context, FunctionDescriptor descriptor)
        {
            var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();
            AuthorizationPolicy policy = AuthUtility.CreateFunctionPolicy();

            // Authenticate the request
            var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);

            // Authorize using the function policy and resource
            var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, descriptor);

            return authorizeResult.Succeeded;
        }

    }
}
