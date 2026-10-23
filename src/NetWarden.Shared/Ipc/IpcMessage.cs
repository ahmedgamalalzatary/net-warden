using System.Text.Json;

namespace NetWarden.Shared.Ipc;

public enum MessageKind
{
    Request,
    Response,
    Event,
}

/// <summary>
/// One frame on the pipe. Requests and responses are paired by <see cref="Id"/>;
/// events are pushed by the service and carry no id.
/// </summary>
public sealed record IpcMessage(
    MessageKind Kind,
    long Id,
    string Method,
    JsonElement? Payload = null,
    string? Error = null);
