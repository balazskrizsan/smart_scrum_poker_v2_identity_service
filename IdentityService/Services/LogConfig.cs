using Serilog;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Json;
using Serilog.Sinks.Network;
using Serilog.Sinks.Network.Formatters;
using Serilog.Sinks.SystemConsole.Themes;

namespace IdentityService.Services;

public class LogLevelMappingJsonFormatter : ITextFormatter
{
    private readonly JsonFormatter _jsonFormatter;

    public LogLevelMappingJsonFormatter()
    {
        _jsonFormatter = new JsonFormatter();
    }

    public void Format(LogEvent logEvent, TextWriter output)
    {
        using var stringWriter = new StringWriter();
        _jsonFormatter.Format(logEvent, stringWriter);
        var json = stringWriter.ToString();

        var levelMapping = new Dictionary<string, string>
        {
            { "Verbose", "TRACE" },
            { "Debug", "DEBUG" },
            { "Information", "INFO" },
            { "Warning", "WARN" },
            { "Error", "ERROR" },
            { "Fatal", "FATAL" }
        };

        foreach (var mapping in levelMapping)
        {
            json = json.Replace($"\"Level\":\"{mapping.Key}\"", $"\"Level\":\"{mapping.Value}\"");
        }

        output.Write(json);
    }
}

public class LogLevelMappingLogstashFormatter : ITextFormatter
{
    private readonly LogstashJsonFormatter _logstashFormatter;

    public LogLevelMappingLogstashFormatter()
    {
        _logstashFormatter = new LogstashJsonFormatter();
    }

    public void Format(LogEvent logEvent, TextWriter output)
    {
        using var stringWriter = new StringWriter();
        _logstashFormatter.Format(logEvent, stringWriter);
        var json = stringWriter.ToString();

        var levelMapping = new Dictionary<string, string>
        {
            { "Verbose", "TRACE" },
            { "Debug", "DEBUG" },
            { "Information", "INFO" },
            { "Warning", "WARN" },
            { "Error", "ERROR" },
            { "Fatal", "FATAL" }
        };

        foreach (var mapping in levelMapping)
        {
            json = json.Replace($"\"level\":\"{mapping.Key}\"", $"\"level\":\"{mapping.Value}\"");
        }

        output.Write(json);
    }
}

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
            loggerConfiguration.WriteTo.Console(formatter: new LogLevelMappingJsonFormatter());
        }
        else
        {
            loggerConfiguration.WriteTo.Console(theme: SystemConsoleTheme.Colored);
        }

        if (logstashEnabled && !string.IsNullOrEmpty(logstashHost))
        {
            var uri = $"tcp://{logstashHost}:{logstashPort}";
            loggerConfiguration.WriteTo.TCPSink(uri, new LogLevelMappingLogstashFormatter());
        }
    }
}