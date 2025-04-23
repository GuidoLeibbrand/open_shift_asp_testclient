using System.Text;
using System.IdentityModel.Tokens.Jwt;
using HelloWorldWithHeaderInformations;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("JwtSettings"));
var app = builder.Build();

var jwtSettings = app.Services.GetRequiredService<IConfiguration>().GetSection("JwtSettings").Get<JwtSettings>();


app.MapGet("/", async (HttpContext context) =>
{
    var headers = context.Request.Headers;
    var headersList = string.Join("<br/>", headers.Select(h => $"<b>{h.Key}</b>: {h.Value}"));

    // JWT aus dem Header extrahieren (Bearer Token)
    string authHeader = context.Request.Headers.Authorization;
    bool tokenIsValid = false;
    string jwtMessage;

    if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer "))
    {
        string token = authHeader.Substring("Bearer ".Length).Trim();

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey))
        };

        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
            tokenIsValid = true;
            jwtMessage = "JWT ist gültig!";
        }
        catch (Exception ex)
        {
            tokenIsValid = false;
            jwtMessage = $"JWT ist ungültig: {ex.Message}";
        }
    }
    else
    {
        jwtMessage = "Kein JWT gefunden oder Header falsch formatiert (erwartet: Bearer TOKEN).";
    }

    var htmlResponse = $@"
    <html>
        <head><title>Hallo & JWT Check</title></head>
        <body>
            <h1>Hallo!</h1>
            <h3>Empfangene Request-Header:</h3>
            <p>{headersList}</p>
            <h3>JWT Validierung:</h3>
            <p>{jwtMessage}</p>
        </body>
    </html>";

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync(htmlResponse);
});

app.Run();
