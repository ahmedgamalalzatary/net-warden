using System.Buffers.Binary;
using System.Text.Json;

namespace NetWarden.Shared.Ipc;

/// <summary>
/// Frames messages as a 4-byte little-endian length followed by UTF-8 JSON.
/// </summary>
public static class MessageFraming
{
    public const int MaxMessageBytes = 16 * 1024 * 1024;

    public static async Task WriteAsync(Stream stream, IpcMessage message, CancellationToken ct = default)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(message, IpcJson.Options);
        if (body.Length > MaxMessageBytes)
            throw new InvalidDataException($"Message is {body.Length} bytes; the limit is {MaxMessageBytes}.");

        byte[] frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Reads one message, or returns null when the stream ends cleanly between messages.</summary>
    public static async Task<IpcMessage?> ReadAsync(Stream stream, CancellationToken ct = default)
    {
        byte[] header = new byte[4];
        if (!await ReadExactAsync(stream, header, allowEof: true, ct).ConfigureAwait(false))
            return null;

        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxMessageBytes)
            throw new InvalidDataException($"Invalid message length {length}.");

        byte[] body = new byte[length];
        await ReadExactAsync(stream, body, allowEof: false, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<IpcMessage>(body, IpcJson.Options)
            ?? throw new InvalidDataException("Message body was null.");
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, bool allowEof, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (allowEof && read == 0)
                    return false;
                throw new EndOfStreamException("Stream ended in the middle of a message.");
            }
            read += n;
        }
        return true;
    }
}
