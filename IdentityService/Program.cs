using System.Security.Cryptography.X509Certificates;
using IdentityServer.Services;
using IdentityService;
using IdentityService.Database;
using IdentityService.Repositories;
using IdentityService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting...");

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var migrationsAssembly = typeof(Config).Assembly.GetName().Name;

builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("user.info.read", policy => policy.RequireClaim("scope", "user.info.read"));
});

builder.Host.UseSerilog((context, lc) =>
{
    lc.MinimumLevel.Debug()
        .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.HostingLifeti,e", LogEventLevel.Information)
        .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
        .MinimumLevel.Override("System", LogEventLevel.Warning)
        .WriteTo.Console(
            outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}",
            theme: AnsiConsoleTheme.Code)
        .Enrich.FromLogContext();
});

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(connectionString, sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly));
});
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddScoped<UserInputValidationService>();
builder.Services.AddScoped<QuicRegisterService>();
builder.Services.AddScoped<RegisterService>();
builder.Services.AddScoped<TokenGeneratorService>();
builder.Services.AddScoped<AwsSesService>();
builder.Services.AddScoped<ITokenValidationService, TokenValidationService>();
builder.Services.AddScoped<IExternalProviderRepository, ExternalProviderRepository>();
builder.Services.AddScoped<IExternalProviderService, ExternalProviderService>();
builder.Services.AddScoped<IUserLookupService, UserLookupService>();
builder.Services.AddScoped<ILoginModelBuilderService, LoginModelBuilderService>();
builder.Services.AddIdentityServer(options =>
    {
        options.Events.RaiseErrorEvents = true;
        options.Events.RaiseInformationEvents = true;
        options.Events.RaiseFailureEvents = true;
        options.Events.RaiseSuccessEvents = true;
        options.IssuerUri = builder.Configuration["IdentityServer:IssuerUri"];
        options.EmitStaticAudienceClaim = false;
    })
    .AddAspNetIdentity<IdentityUser>()
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiResources(Config.ApiResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients(builder.Configuration))
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = db =>
            db.UseNpgsql(connectionString, opt => { opt.MigrationsAssembly(migrationsAssembly); });
    });

builder.WebHost.ConfigureKestrel(options =>
{
    var port = int.Parse(builder.Configuration["IdentityServer:Port"]);
    var certPath = builder.Configuration["Certificate:Path"];
    var certPassword = builder.Configuration["Certificate:Password"];
    
    options.ListenAnyIP(port, listenOptions =>
    {
        try
        {
            listenOptions.UseHttps(new X509Certificate2(certPath, certPassword));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Certificate error: {ex.Message}");
        }
    });
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseIdentityServer();

app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages().RequireAuthorization();

if (args.Contains("/seed"))
{
    Log.Information("Seeding database");
    SeedData.EnsureSeedData(app);
    Log.Information("Seeding complete");
}
else
{
    app.Run();
}