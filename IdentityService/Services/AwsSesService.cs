using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace IdentityService.Services;

public class AwsSesService(
    HttpClient httpClient,
    TokenGeneratorService tokenGeneratorService,
    ILogger<AwsSesService> logger
)
{
    public class EmailRequest
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string Text { get; set; }
        public string Html { get; set; }
    }

    public class TemplatedEmailRequest
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string HtmlTemplate { get; set; }
        public string TextTemplate { get; set; }
        public Dictionary<string, string> TemplateVariables { get; set; }
    }

    public class TemplatedEmailByIdRequest
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string TemplateId { get; set; }
        public Dictionary<string, string> TemplateVariables { get; set; }
    }

    public class EmailResponse
    {
        public string MessageId { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public async Task<EmailResponse> SendEmailAsync(EmailRequest request)
    {
        return await SendSesRequestAsync("/api/v1/ses/send", request);
    }

    public async Task<EmailResponse> SendTemplatedEmailAsync(TemplatedEmailRequest request)
    {
        return await SendSesRequestAsync("/api/v1/ses/send-templated", request);
    }

    public async Task<EmailResponse> SendTemplatedEmailByIdAsync(TemplatedEmailByIdRequest request)
    {
        return await SendSesRequestAsync("/api/v1/ses/send-templated-by-id", request);
    }

    private async Task<EmailResponse> SendSesRequestAsync<T>(string endpoint, T request)
    {
        try
        {
            var token = await tokenGeneratorService.GenerateClientCredentialsTokenAsync(
                "smart_scrum_poker_aws",
                "aws.ses"
            );

            if (string.IsNullOrEmpty(token))
            {
                return new EmailResponse
                {
                    Success = false,
                    Error = "AWS token not found in configuration"
                };
            }

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await DoPostAsync(endpoint, request);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var messageId = JsonSerializer.Deserialize<JsonElement>(responseContent);

                return new EmailResponse
                {
                    Success = true,
                    MessageId = messageId.GetProperty("messageId").GetString()
                };
            }

            var errorContent = await response.Content.ReadAsStringAsync();
            logger.LogError("Email sending failed: {StatusCode} - {Error}", response.StatusCode, errorContent);

            return new EmailResponse
            {
                Success = false,
                Error = $"HTTP {response.StatusCode}: {errorContent}"
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Exception occurred while sending email");
            return new EmailResponse
            {
                Success = false,
                Error = ex.Message
            };
        }
    }

    private async Task<HttpResponseMessage> DoPostAsync<T>(string endpoint, T request)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        var jsonContent = JsonSerializer.Serialize(request, jsonOptions);
        var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

        try
        {
            return await httpClient.PostAsync($"https://localhost.balazskrizsan.com:8080{endpoint}", content);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Exception occurred while sending email request to {Endpoint}", endpoint);
            throw; // Rethrow the exception after logging it
        }
    }
}
