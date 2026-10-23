using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetWarden.Shared.Ipc;

public static class IpcJson
{
    public static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = false,
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    public static JsonElement? ToElement(object? value) =>
        value is null ? null : JsonSerializer.SerializeToElement(value, value.GetType(), Options);

    public static T? FromElement<T>(JsonElement? element) =>
        element is { } e && e.ValueKind != JsonValueKind.Null ? e.Deserialize<T>(Options) : default;
}
