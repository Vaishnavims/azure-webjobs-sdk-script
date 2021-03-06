﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Script.WebHost.Middleware;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public static class WebJobsApplicationBuilderExtension
    {
        public static IApplicationBuilder UseWebJobsScriptHost(this IApplicationBuilder builder, IApplicationLifetime applicationLifetime)
        {
            return UseWebJobsScriptHost(builder, applicationLifetime, null);
        }

        public static IApplicationBuilder UseWebJobsScriptHost(this IApplicationBuilder builder, IApplicationLifetime applicationLifetime, Action<WebJobsRouteBuilder> routes)
        {
            builder.UseMiddleware<HttpExceptionMiddleware>();
            builder.UseMiddleware<FunctionInvocationMiddleware>();
            builder.UseMiddleware<HostWarmupMiddleware>();

            // Ensure the HTTP binding routing is registered after all middleware
            builder.UseHttpBindingRouting(applicationLifetime, routes);

            builder.UseMvc(r =>
            {
                r.MapRoute(name: "Home",
                    template: string.Empty,
                    defaults: new { controller = "Home", action = "Get" });
            });

            return builder;
        }
    }
}
