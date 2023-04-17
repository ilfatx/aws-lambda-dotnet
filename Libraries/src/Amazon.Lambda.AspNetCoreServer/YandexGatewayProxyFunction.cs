using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;

using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.AspNetCoreServer.Internal;
using Microsoft.AspNetCore.Http.Features.Authentication;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;

namespace Amazon.Lambda.AspNetCoreServer
{
    /// <summary>
    /// YandexGatewayProxyFunction is the base class for Yandex Functions hosting the ASP.NET Core framework and exposed to the web via API Gateway.
    /// 
    /// The derived class implements the Init method similar to Main function in the ASP.NET Core. The function handler for the Yandex Functions will point
    /// to this base class.
    /// </summary>
    public abstract class YandexGatewayProxyFunction : AbstractAspNetCoreFunction<YandexGatewayProxyRequest, YandexGatewayProxyResponse>
    {


        /// <summary>
        /// Default Constructor. The ASP.NET Core Framework will be initialized as part of the construction.
        /// </summary>
        protected YandexGatewayProxyFunction()
            : base(StartupMode.FirstRequest)
        {

        }

        public async Task StartAsync()
        {
            IHostBuilder builder = Host.CreateDefaultBuilder();

            builder.ConfigureServices(services =>
            {
                Utilities.EnsureLambdaServerRegistered(services, typeof(LambdaServer));
            });

            builder.ConfigureWebHost(webHostBuilder =>
            {
                Init(webHostBuilder);
            });
            Init(builder);

            var host = builder.Build();
            PostCreateHost(host);
            await host.StartAsync();
            this._hostServices = host.Services;
            _server = this._hostServices.GetService(typeof(Microsoft.AspNetCore.Hosting.Server.IServer)) as LambdaServer;
            _logger = ActivatorUtilities.CreateInstance<Logger<AbstractAspNetCoreFunction>>(this._hostServices);
        }

        public async Task<YandexGatewayProxyResponse> FunctionHandler(YandexGatewayProxyRequest request)
        {
            if (!IsStarted)
            {
                await StartAsync();
            }

            return await this.FunctionHandlerAsync(request, null);
        }

        private protected override void InternalCustomResponseExceptionHandling(YandexGatewayProxyResponse apiGatewayResponse, ILambdaContext lambdaContext, Exception ex)
        {
            apiGatewayResponse.multiValueHeaders["ErrorType"] = new List<string> { ex.GetType().Name };
        }


        /// <summary>
        /// Convert the JSON document received from API Gateway into the InvokeFeatures object.
        /// InvokeFeatures is then passed into IHttpApplication to create the ASP.NET Core request objects.
        /// </summary>
        /// <param name="features"></param>
        /// <param name="apiGatewayRequest"></param>
        /// <param name="lambdaContext"></param>
        protected override void MarshallRequest(InvokeFeatures features, YandexGatewayProxyRequest apiGatewayRequest, ILambdaContext lambdaContext)
        {
            {
                var authFeatures = (IHttpAuthenticationFeature)features;

                var authorizer = apiGatewayRequest?.requestContext?.authorizer;

                if (authorizer != null)
                {
                    // handling claims output from cognito user pool authorizer
                    if (authorizer.Claims != null && authorizer.Claims.Count != 0)
                    {
                        var identity = new ClaimsIdentity(authorizer.Claims.Select(
                            entry => new Claim(entry.Key, entry.Value.ToString())), "AuthorizerIdentity");

                        _logger.LogDebug(
                            $"Configuring HttpContext.User with {authorizer.Claims.Count} claims coming from API Gateway's Request Context");
                        authFeatures.User = new ClaimsPrincipal(identity);
                    }
                    else
                    {
                        // handling claims output from custom lambda authorizer
                        var identity = new ClaimsIdentity(
                            authorizer.Where(x => x.Value != null && !string.Equals(x.Key, "claims", StringComparison.OrdinalIgnoreCase))
                                .Select(entry => new Claim(entry.Key, entry.Value.ToString())), "AuthorizerIdentity");

                        _logger.LogDebug(
                            $"Configuring HttpContext.User with {authorizer.Count} claims coming from API Gateway's Request Context");
                        authFeatures.User = new ClaimsPrincipal(identity);
                    }
                }

                // Call consumers customize method in case they want to change how API Gateway's request
                // was marshalled into ASP.NET Core request.
                PostMarshallHttpAuthenticationFeature(authFeatures, apiGatewayRequest, lambdaContext);
            }
            {
                var requestFeatures = (IHttpRequestFeature)features;
                requestFeatures.Scheme = "https";
                requestFeatures.Method = apiGatewayRequest.httpMethod;

                string path = null;

                // Replaces {proxy+} in path, if exists
                if (apiGatewayRequest.pathParameters != null && apiGatewayRequest.pathParameters.TryGetValue("proxy", out var proxy) &&
                    !string.IsNullOrEmpty(apiGatewayRequest.resource))
                {
                    var proxyPath = proxy;
                    path = apiGatewayRequest.resource.Replace("{proxy+}", proxyPath);

                    // Adds all the rest of non greedy parameters in apiGateway.Resource to the path
                    foreach (var pathParameter in apiGatewayRequest.pathParameters.Where(pp => pp.Key != "proxy"))
                    {
                        path = path.Replace($"{{{pathParameter.Key}}}", pathParameter.Value);
                    }
                }
 
                if (string.IsNullOrEmpty(path))
                {
                    path = apiGatewayRequest.path;
                }

                if (!path.StartsWith("/"))
                {
                    path = "/" + path;
                }

                var rawQueryString = Utilities.CreateQueryStringParameters(
                    apiGatewayRequest.queryStringParameters, apiGatewayRequest.multiValueQueryStringParameters, true);

                requestFeatures.RawTarget = apiGatewayRequest.path + rawQueryString;
                requestFeatures.QueryString = rawQueryString;
                requestFeatures.Path = path;

                requestFeatures.PathBase = string.Empty;
                if (!string.IsNullOrEmpty(apiGatewayRequest?.requestContext?.path))
                {
                    // This is to cover the case where the request coming in is https://myapigatewayid.execute-api.us-west-2.amazonaws.com/Prod where
                    // Prod is the stage name and there is no ending '/'. Path will be set to '/' so to make sure we detect the correct base path
                    // append '/' on the end to make the later EndsWith and substring work correctly.
                    var requestContextPath = apiGatewayRequest.requestContext.path;
                    if (path.EndsWith("/") && !requestContextPath.EndsWith("/"))
                    {
                        requestContextPath += "/";
                    }
                    else if (!path.EndsWith("/") && requestContextPath.EndsWith("/"))
                    {
                        // Handle a trailing slash in the request path: e.g. https://myapigatewayid.execute-api.us-west-2.amazonaws.com/Prod/foo/
                        requestFeatures.Path = path += "/";
                    }

                    if (requestContextPath.EndsWith(path))
                    {
                        requestFeatures.PathBase = requestContextPath.Substring(0,
                            requestContextPath.Length - requestFeatures.Path.Length);
                    }
                }

                requestFeatures.Path = Utilities.DecodeResourcePath(requestFeatures.Path);

                Utilities.SetHeadersCollection(requestFeatures.Headers, apiGatewayRequest.headers, apiGatewayRequest.multiValueHeaders);

                if (!requestFeatures.Headers.ContainsKey("Host"))
                {
                    var apiId = apiGatewayRequest?.requestContext?.apiId ?? "";
                    var stage = apiGatewayRequest?.requestContext?.stage ?? "";

                    requestFeatures.Headers["Host"] = $"apigateway-{apiId}-{stage}";
                }


                if (!string.IsNullOrEmpty(apiGatewayRequest.body))
                {
                    requestFeatures.Body = Utilities.ConvertLambdaRequestBodyToAspNetCoreBody(apiGatewayRequest.body, apiGatewayRequest.isBase64Encoded);
                }

                // Make sure the content-length header is set if header was not present.
                const string contentLengthHeaderName = "Content-Length";
                if (!requestFeatures.Headers.ContainsKey(contentLengthHeaderName))
                {
                    requestFeatures.Headers[contentLengthHeaderName] = requestFeatures.Body == null ? "0" : requestFeatures.Body.Length.ToString(CultureInfo.InvariantCulture);
                }


                // Call consumers customize method in case they want to change how API Gateway's request
                // was marshalled into ASP.NET Core request.
                PostMarshallRequestFeature(requestFeatures, apiGatewayRequest, lambdaContext);
            }


            {
                // set up connection features
                var connectionFeatures = (IHttpConnectionFeature)features;

                if (!string.IsNullOrEmpty(apiGatewayRequest?.requestContext?.identity?.sourceIp) &&
                    IPAddress.TryParse(apiGatewayRequest.requestContext.identity.sourceIp, out var remoteIpAddress))
                {
                    connectionFeatures.RemoteIpAddress = remoteIpAddress;
                }

                if (apiGatewayRequest?.headers?.TryGetValue("X-Forwarded-Port", out var forwardedPort) == true)
                {
                    connectionFeatures.RemotePort = int.Parse(forwardedPort, CultureInfo.InvariantCulture);
                }

                // Call consumers customize method in case they want to change how API Gateway's request
                // was marshalled into ASP.NET Core request.
                PostMarshallConnectionFeature(connectionFeatures, apiGatewayRequest, lambdaContext);
            }

            {
                var tlsConnectionFeature = (ITlsConnectionFeature)features;
                var clientCertPem = apiGatewayRequest?.requestContext?.identity?.clientCert?.ClientCertPem;
                if (clientCertPem != null)
                {
                    tlsConnectionFeature.ClientCertificate = Utilities.GetX509Certificate2FromPem(clientCertPem);
                }
                PostMarshallTlsConnectionFeature(tlsConnectionFeature, apiGatewayRequest, lambdaContext);
            }
        }

        /// <summary>
        /// Convert the response coming from ASP.NET Core into YandexGatewayProxyResponse which is
        /// serialized into the JSON object that API Gateway expects.
        /// </summary>
        /// <param name="responseFeatures"></param>
        /// <param name="statusCodeIfNotSet">Sometimes the ASP.NET server doesn't set the status code correctly when successful, so this parameter will be used when the value is 0.</param>
        /// <param name="lambdaContext"></param>
        /// <returns><see cref="APIGatewayProxyResponse"/></returns>
        protected override YandexGatewayProxyResponse MarshallResponse(IHttpResponseFeature responseFeatures, ILambdaContext lambdaContext, int statusCodeIfNotSet = 200)
        {
            var response = new YandexGatewayProxyResponse
            {
                statusCode = responseFeatures.StatusCode != 0 ? responseFeatures.StatusCode : statusCodeIfNotSet
            };

            string contentType = null;
            string contentEncoding = null;
            if (responseFeatures.Headers != null)
            {
                response.multiValueHeaders = new Dictionary<string, IList<string>>();

                response.headers = new Dictionary<string, string>();
                foreach (var kvp in responseFeatures.Headers)
                {
                    response.multiValueHeaders[kvp.Key] = kvp.Value.ToList();

                    // Remember the Content-Type for possible later use
                    if (kvp.Key.Equals("Content-Type", StringComparison.CurrentCultureIgnoreCase) && response.multiValueHeaders[kvp.Key].Count > 0)
                    {
                        contentType = response.multiValueHeaders[kvp.Key][0];
                    }
                    else if (kvp.Key.Equals("Content-Encoding", StringComparison.CurrentCultureIgnoreCase) && response.multiValueHeaders[kvp.Key].Count > 0)
                    {
                        contentEncoding = response.multiValueHeaders[kvp.Key][0];
                    }
                }
            }

            if (contentType == null)
            {
                response.multiValueHeaders["Content-Type"] = new List<string>() { null };
            }

            if (responseFeatures.Body != null)
            {
                // Figure out how we should treat the response content, check encoding first to see if body is compressed, then check content type
                var rcEncoding = GetResponseContentEncodingForContentEncoding(contentEncoding);
                if (rcEncoding != ResponseContentEncoding.Base64)
                {
                    rcEncoding = GetResponseContentEncodingForContentType(contentType);
                }

                (response.body, response.isBase64Encoded) = Utilities.ConvertAspNetCoreBodyToLambdaBody(responseFeatures.Body, rcEncoding);

            }

            PostMarshallResponseFeature(responseFeatures, response, lambdaContext);

            _logger.LogDebug($"Response Base 64 Encoded: {response.isBase64Encoded}");

            return response;
        }
    }
}
