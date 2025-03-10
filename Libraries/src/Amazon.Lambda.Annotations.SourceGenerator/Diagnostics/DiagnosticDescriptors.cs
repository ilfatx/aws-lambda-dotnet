using System;
using Microsoft.CodeAnalysis;
using Amazon.Lambda.Annotations.APIGateway;

namespace Amazon.Lambda.Annotations.SourceGenerator.Diagnostics
{
    public static class DiagnosticDescriptors
    {
        /// Generic errors
        public static readonly DiagnosticDescriptor UnhandledException = new DiagnosticDescriptor(id: "AWSLambda0001",
            title: "Unhandled exception",
            messageFormat: "This is a bug. Please run the build with detailed verbosity (dotnet build --verbosity detailed) and file a bug at https://github.com/aws/aws-lambda-dotnet with the build output and stack trace {0}.",
            category: "AWSLambda",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "{0}.",
            helpLinkUri: "https://github.com/aws/aws-lambda-dotnet");

        /// AWSLambdaCSharpGenerator starts from 0101
        public static readonly DiagnosticDescriptor MultipleStartupNotAllowed = new DiagnosticDescriptor(id: "AWSLambda0101",
            title: "Multiple LambdaStartup classes not allowed",
            messageFormat: "Multiple LambdaStartup classes are not allowed in Lambda AWSProjectType",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true);

        public static readonly DiagnosticDescriptor MultipleEventsNotSupported = new DiagnosticDescriptor(id: "AWSLambda0102",
            title: "Multiple events on Lambda function not supported",
            messageFormat: "Multiple event attributes on LambdaFunction are not supported",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true);

        public static readonly DiagnosticDescriptor CodeGeneration = new DiagnosticDescriptor(id: "AWSLambda0103",
            title: "Generated Code",
            messageFormat: $"{{0}}{Environment.NewLine}{{1}}",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Info,
            isEnabledByDefault: true);

        public static readonly DiagnosticDescriptor MissingDependencies = new DiagnosticDescriptor(id: "AWSLambda0104",
            title: "Missing reference to a required dependency",
            messageFormat: "Your project has a missing required package dependency. Please add a reference to the following package: {0}",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true);

        public static readonly DiagnosticDescriptor HttpResultsOnNonApiFunction = new DiagnosticDescriptor(id: "AWSLambda0105",
            title: $"Invalid return type {nameof(IHttpResult)}",
            messageFormat: $"{nameof(IHttpResult)} is not a valid return type for LambdaFunctions without {nameof(HttpApiAttribute)} or {nameof(RestApiAttribute)} attributes",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true);

        public static readonly  DiagnosticDescriptor InvalidResourceName = new DiagnosticDescriptor(id: "AWSLambda0106",
            title: $"Invalid CloudFormation resource name",
            messageFormat: "The specified CloudFormation resource name is not valid. It must only contain alphanumeric characters.",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true);

        public static readonly DiagnosticDescriptor CodeGenerationFailed = new DiagnosticDescriptor(id: "AWSLambda0107",
            title: "Failed Code Generation",
            messageFormat: $"{{0}}{Environment.NewLine}{{1}}",
            category: "AWSLambdaCSharpGenerator",
            DiagnosticSeverity.Error,
            isEnabledByDefault: true);
    }
}