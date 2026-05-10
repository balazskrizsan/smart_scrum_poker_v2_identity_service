using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace IdentityService.Services
{
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

        public class EmailResponse
        {
            public string MessageId { get; set; }
            public bool Success { get; set; }
            public string Error { get; set; }
        }

        public async Task<EmailResponse> SendEmailAsync(EmailRequest request)
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

                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var jsonContent = JsonSerializer.Serialize(request, jsonOptions);
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var response = await httpClient.PostAsync("https://localhost.balazskrizsan.com:8080/api/v1/ses/send", content);

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
    }
}
