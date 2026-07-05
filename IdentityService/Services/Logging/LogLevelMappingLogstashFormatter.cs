using Serilog.Events;
using Serilog.Formatting;
using Serilog.Sinks.Network.Formatters;
using System.Text.Json;

namespace IdentityService.Services;

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

        // Flatten Properties to top level
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement.Clone();
        var outputObj = new Dictionary<string, JsonElement>();

        foreach (var property in root.EnumerateObject())
        {
            if (property.NameEquals("fields"))
            {
                // Move fields (Logstash equivalent of Properties) content to top level
                foreach (var prop in property.Value.EnumerateObject())
                {
                    outputObj[prop.Name] = prop.Value.Clone();
                }
            }
            else
            {
                outputObj[property.Name] = property.Value.Clone();
            }
        }

        var options = new JsonSerializerOptions { WriteIndented = false };
        var flattenedJson = JsonSerializer.Serialize(outputObj, options);
        output.Write(flattenedJson);
        output.WriteLine();
    }
}
