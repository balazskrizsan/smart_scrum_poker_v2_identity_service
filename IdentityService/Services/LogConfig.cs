using Serilog;
using Serilog.Events;
using Serilog.Formatting.Json;
using Serilog.Sinks.Network;

namespace IdentityService.Services;

public static class LogConfig
{
    public static void ConfigureLogger(
        IConfiguration configuration,
        string envName,
        string appName,
        LogState logState,
        LoggerConfiguration loggerConfiguration)
    {
        var logType = configuration["Logging:LogType"] ?? "JSON";
        var logstashEnabled = configuration.GetValue<bool>("Logging:LogstashEnabled");
        var logstashHost = configuration["Logging:LogstashHost"];
        var logstashPort = configuration.GetValue<int>("Logging:LogstashPort");

        loggerConfiguration
            .MinimumLevel.Debug()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.HostingLifetime", LogEventLevel.Information)
            .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.With(new LogContextEnricher(envName, appName, logState));

        if (logType.ToUpper() == "JSON")
        {
            loggerConfiguration.WriteTo.Console(formatter: new JsonFormatter());
        }
        else
        {
            loggerConfiguration.WriteTo.Console();
        }

        if (logstashEnabled && !string.IsNullOrEmpty(logstashHost))
        {
            var uri = $"tcp://{logstashHost}:{logstashPort}";
            loggerConfiguration.WriteTo.TCPSink(uri);
        }
    }
}
