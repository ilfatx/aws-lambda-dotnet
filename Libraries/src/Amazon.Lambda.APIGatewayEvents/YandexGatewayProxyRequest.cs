﻿namespace Amazon.Lambda.APIGatewayEvents
{
    using System.Collections.Generic;

    /// <summary>
    /// For request coming in from API Gateway proxy
    /// http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html
    /// </summary>
    public class YandexGatewayProxyRequest
    {
        /// <summary>
        /// The resource path defined in API Gateway
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public string resource { get; set; }

        /// <summary>
        /// The url path for the caller
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public string path { get; set; }

        /// <summary>
        /// The HTTP method used
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public string httpMethod { get; set; }

        /// <summary>
        /// The headers sent with the request. This collection will only contain a single value for a header. 
        /// 
        /// API Gateway will populate both the Headers and MultiValueHeaders collection for every request. If multiple values
        /// are set for a header then the Headers collection will just contain the last value.
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public IDictionary<string, string> headers { get; set; }

        /// <summary>
        /// The headers sent with the request. This collection supports multiple values for a single header.
        /// 
        /// API Gateway will populate both the Headers and MultiValueHeaders collection for every request. If multiple values
        /// are set for a header then the Headers collection will just contain the last value.
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public IDictionary<string, IList<string>> multiValueHeaders { get; set; }

        /// <summary>
        /// The query string parameters that were part of the request. This collection will only contain a single value for a query parameter.
        /// 
        /// API Gateway will populate both the QueryStringParameters and MultiValueQueryStringParameters collection for every request. If multiple values
        /// are set for a query parameter then the QueryStringParameters collection will just contain the last value.
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public IDictionary<string, string> queryStringParameters { get; set; }

        /// <summary>
        /// The query string parameters that were part of the request. This collection supports multiple values for a single query parameter.
        /// 
        /// API Gateway will populate both the QueryStringParameters and MultiValueQueryStringParameters collection for every request. If multiple values
        /// are set for a query parameter then the QueryStringParameters collection will just contain the last value.
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public IDictionary<string, IList<string>> multiValueQueryStringParameters { get; set; }

        /// <summary>
        /// The path parameters that were part of the request
        /// <para>
        /// This field is only set for REST API requests.
        /// </para>
        /// </summary>
        public IDictionary<string, string> pathParameters { get; set; }

        /// <summary>
        /// The stage variables defined for the stage in API Gateway
        /// </summary>
        public IDictionary<string, string> stageVariables { get; set; }

        /// <summary>
        /// The request context for the request
        /// </summary>
        public YandexProxyRequestContext requestContext { get; set; }

        /// <summary>
        /// The HTTP request body.
        /// </summary>
        public string body { get; set; }

        /// <summary>
        /// True if the body of the request is base 64 encoded.
        /// </summary>
        public bool isBase64Encoded { get; set; }

        /// <summary>
        /// The ProxyRequestContext contains the information to identify the AWS account and resources invoking the 
        /// Lambda function. It also includes Cognito identity information for the caller.
        /// </summary>
        public class YandexProxyRequestContext
        {
            /// <summary>
            /// The resource full path including the API Gateway stage
            /// <para>
            /// This field is only set for REST API requests.
            /// </para>
            /// </summary>
            public string path { get; set; }

            /// <summary>
            /// The account id that owns the executing Lambda function
            /// </summary>
            public string accountId { get; set; }

            /// <summary>
            /// The resource id.
            /// </summary>
            public string resourceId { get; set; }


            /// <summary>
            /// The API Gateway stage name
            /// </summary>
            public string stage { get; set; }

            /// <summary>
            /// The unique request id
            /// </summary>
            public string requestId { get; set; }

            /// <summary>
            /// The identity information for the request caller
            /// </summary>
            public YandexRequestIdentity identity { get; set; }

            /// <summary>
            /// The resource path defined in API Gateway
            /// <para>
            /// This field is only set for REST API requests.
            /// </para>
            /// </summary>
            public string resourcePath { get; set; }

            /// <summary>
            /// The HTTP method used
            /// <para>
            /// This field is only set for REST API requests.
            /// </para>
            /// </summary>
            public string httpMethod { get; set; }

            /// <summary>
            /// The API Gateway rest API Id.
            /// </summary>
            public string apiId { get; set; }

            /// <summary>
            /// An automatically generated ID for the API call, which contains more useful information for debugging/troubleshooting.
            /// </summary>
            public string extendedRequestId { get; set; }

            /// <summary>
            /// The connectionId identifies a unique client connection in a WebSocket API.
            /// <para>
            /// This field is only set for WebSocket API requests.
            /// </para>
            /// </summary>
            public string connectionId { get; set; }

            /// <summary>
            /// The Epoch-formatted connection time in a WebSocket API.
            /// <para>
            /// This field is only set for WebSocket API requests.
            /// </para>
            /// </summary>
            public long connectedAt { get; set; }

            /// <summary>
            /// A domain name for the WebSocket API. This can be used to make a callback to the client (instead of a hard-coded value).
            /// <para>
            /// This field is only set for WebSocket API requests.
            /// </para>
            /// </summary>
            public string domainName { get; set; }

            /// <summary>
            /// The first label of the DomainName. This is often used as a caller/customer identifier.
            /// </summary>
            public string domainPrefix { get; set; }

            /// <summary>
            /// The event type: CONNECT, MESSAGE, or DISCONNECT.
            /// <para>
            /// This field is only set for WebSocket API requests.
            /// </para>
            /// </summary>
            public string eventType { get; set; }

            /// <summary>
            /// A unique server-side ID for a message. Available only when the $context.eventType is MESSAGE.
            /// <para>
            /// This field is only set for WebSocket API requests.
            /// </para>
            /// </summary>
            public string messageId { get; set; }

            /// <summary>
            /// The selected route key.
            /// <para>
            /// This field is only set for WebSocket API requests.
            /// </para>
            /// </summary>
            public string routeKey { get; set; }


            /// <summary>
            /// The APIGatewayCustomAuthorizerContext containing the custom properties set by a custom authorizer.
            /// </summary>
            public APIGatewayCustomAuthorizerContext authorizer { get; set; }
            
            /// <summary>
            /// Gets and sets the operation name.
            /// </summary>
            public string operationName { get; set; }
            
            /// <summary>
            /// Gets and sets the error.
            /// </summary>
            public string error { get; set; }
            
            /// <summary>
            /// Gets and sets the integration latency.
            /// </summary>
            public string integrationLatency { get; set; }
            
            /// <summary>
            /// Gets and sets the message direction.
            /// </summary>
            public string messageDirection { get; set; }
            
            /// <summary>
            /// Gets and sets the request time.
            /// </summary>
            public string requestTime { get; set; }
            
            /// <summary>
            /// Gets and sets the request time as an epoch.
            /// </summary>
            public long requestTimeEpoch { get; set; }
            
            /// <summary>
            /// Gets and sets the status.
            /// </summary>
            public string status { get; set; }

        }

        /// <summary>
        /// The RequestIdentity contains identity information for the request caller.
        /// </summary>
        public class YandexRequestIdentity
        {

            /// <summary>
            /// The Cognito identity pool id.
            /// </summary>
            public string cognitoIdentityPoolId { get; set; }

            /// <summary>
            /// The account id of the caller.
            /// </summary>
            public string accountId { get; set; }

            /// <summary>
            /// The cognito identity id.
            /// </summary>
            public string cognitoIdentityId { get; set; }

            /// <summary>
            /// The caller
            /// </summary>
            public string caller { get; set; }

            /// <summary>
            /// The API Key
            /// </summary>
            public string apiKey { get; set; }

            /// <summary>
            /// The API Key ID
            /// </summary>
            public string apiKeyId { get; set; }
            
            /// <summary>
            /// The Access Key
            /// </summary>
            public string accessKey { get; set; }

            /// <summary>
            /// The source IP of the request
            /// </summary>
            public string sourceIp { get; set; }

            /// <summary>
            /// The Cognito authentication type used for authentication
            /// </summary>
            public string cognitoAuthenticationType { get; set; }

            /// <summary>
            /// The Cognito authentication provider
            /// </summary>
            public string cognitoAuthenticationProvider { get; set; }

            /// <summary>
            /// The user arn
            /// </summary>
            public string userArn { get; set; }

            /// <summary>
            /// The user agent
            /// </summary>
            public string userAgent { get; set; }

            /// <summary>
            /// The user
            /// </summary>
            public string user { get; set; }


            /// <summary>
            /// Properties for a client certificate.
            /// </summary>
            public ProxyRequestClientCert clientCert { get; set; }
        }

        /// <summary>
        /// Container for the properties of the client certificate.
        /// </summary>
        public class ProxyRequestClientCert
        {
            /// <summary>
            /// The PEM-encoded client certificate that the client presented during mutual TLS authentication. 
            /// Present when a client accesses an API by using a custom domain name that has mutual 
            /// TLS enabled. Present only in access logs if mutual TLS authentication fails.
            /// </summary>
            public string ClientCertPem { get; set; }

            /// <summary>
            /// The distinguished name of the subject of the certificate that a client presents. 
            /// Present when a client accesses an API by using a custom domain name that has 
            /// mutual TLS enabled. Present only in access logs if mutual TLS authentication fails.
            /// </summary>
            public string SubjectDN { get; set; }

            /// <summary>
            /// The distinguished name of the issuer of the certificate that a client presents. 
            /// Present when a client accesses an API by using a custom domain name that has 
            /// mutual TLS enabled. Present only in access logs if mutual TLS authentication fails.
            /// </summary>
            public string IssuerDN { get; set; }

            /// <summary>
            /// The serial number of the certificate. Present when a client accesses an API by 
            /// using a custom domain name that has mutual TLS enabled. 
            /// Present only in access logs if mutual TLS authentication fails.
            /// </summary>
            public string SerialNumber { get; set; }

            /// <summary>
            /// The rules for when the client cert is valid.
            /// </summary>
            public ClientCertValidity Validity { get; set; }
        }

        /// <summary>
        /// Container for the validation properties of a client cert.
        /// </summary>
        public class ClientCertValidity
        {
            /// <summary>
            /// The date before which the certificate is invalid. Present when a client accesses an API by using a custom domain name 
            /// that has mutual TLS enabled. Present only in access logs if mutual TLS authentication fails.
            /// </summary>
            public string NotBefore { get; set; }

            /// <summary>
            /// The date after which the certificate is invalid. Present when a client accesses an API by using a custom domain name that 
            /// has mutual TLS enabled. Present only in access logs if mutual TLS authentication fails.
            /// </summary>
            public string NotAfter { get; set; }
        }
    }
}
