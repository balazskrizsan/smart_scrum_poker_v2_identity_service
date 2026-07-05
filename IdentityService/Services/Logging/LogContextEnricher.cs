using Serilog.Core;
using Serilog.Events;

namespace IdentityService.Services;

public class LogContextEnricher : ILogEventEnricher
{
    private readonly string _envName;
    private readonly string _appName;
    private readonly LogState _logState;

    public LogContextEnricher(string envName, string appName, LogState logState)
    {
        _envName = envName;
        _appName = appName;
        _logState = logState;
    }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("env", _envName));
        
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("app", _appName));
        
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("long_term", _logState.GetLongTermLogState()));
    }
}
