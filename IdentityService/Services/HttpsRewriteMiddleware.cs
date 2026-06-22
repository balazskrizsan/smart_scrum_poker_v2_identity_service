using System.Text.Json;
using System.Text.Json.Nodes;

namespace IdentityService.Services;

public class HttpsRewriteMiddleware
{
    private readonly RequestDelegate _next;
    private readonly bool _forceHttps;

    public HttpsRewriteMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _forceHttps = configuration.GetValue<bool>("IdentityServer:ForceHttpsRewrite", false);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_forceHttps || context.Request.Path != "/.well-known/openid-configuration")
        {
            await _next(context);
            return;
        }

        var originalBody = context.Response.Body;
        using var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        await _next(context);

        memoryStream.Seek(0, SeekOrigin.Begin);
        var json = await JsonSerializer.DeserializeAsync<JsonObject>(memoryStream);
        
        if (json != null)
        {
            RewriteUrlsToHttps(json);
            
            context.Response.Body = originalBody;
            context.Response.ContentLength = null;
            await context.Response.WriteAsync(json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            memoryStream.Seek(0, SeekOrigin.Begin);
            await memoryStream.CopyToAsync(originalBody);
        }
    }

    private void RewriteUrlsToHttps(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            foreach (var property in obj.ToList())
            {
                if (property.Value is JsonValue value && value.TryGetValue(out string? strValue))
                {
                    if (strValue != null && strValue.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    {
                        obj[property.Key] = strValue.Replace("http://", "https://", StringComparison.OrdinalIgnoreCase);
                    }
                }
                else if (property.Value is JsonNode childNode)
                {
                    RewriteUrlsToHttps(childNode);
                }
            }
        }
        else if (node is JsonArray array)
        {
            foreach (var item in array)
            {
                RewriteUrlsToHttps(item);
            }
        }
    }
}
