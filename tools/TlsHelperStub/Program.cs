using System.Text.Json;

var requestJson = Console.In.ReadToEnd();
var stubPath = args.Length > 0 ? args[0] : null;
if (!string.IsNullOrWhiteSpace(stubPath) && File.Exists(stubPath))
{
    await Console.Out.WriteAsync(File.ReadAllText(stubPath));
    return;
}

var response = BuildResponse(requestJson);
await Console.Out.WriteAsync(JsonSerializer.Serialize(response));

static object BuildResponse(string requestJson)
{
    string? host = null;

    if (!string.IsNullOrWhiteSpace(requestJson))
    {
        try
        {
            using var document = JsonDocument.Parse(requestJson);
            if (document.RootElement.TryGetProperty("host", out var hostElement))
            {
                host = hostElement.GetString();
            }
        }
        catch
        {
            // Return the standard stub failure below.
        }
    }

    return new
    {
        success = false,
        fetchSource = "TlsHelper",
        errorCode = "NotImplemented",
        errorMessage = "The TLS helper process wiring is active, but the real TLS capture implementation is not in place yet.",
        serverSentChain = Array.Empty<object>(),
        notes = host is null
            ? new[] { "Received helper invocation." }
            : new[] { $"Received helper invocation for host '{host}'." }
    };
}
