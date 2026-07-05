using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Json;
using System.Text.Json;

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

        // Flatten Properties to top level
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement.Clone();
        var outputObj = new Dictionary<string, JsonElement>();

        foreach (var property in root.EnumerateObject())
        {
            if (property.NameEquals("Properties"))
            {
                // Move Properties content to top level
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
