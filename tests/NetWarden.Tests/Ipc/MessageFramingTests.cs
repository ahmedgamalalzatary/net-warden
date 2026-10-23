using System.Buffers.Binary;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Ipc;

public class MessageFramingTests
{
    [Fact]
    public async Task RoundTrips_message_with_payload()
    {
        var stream = new MemoryStream();
        var original = new IpcMessage(MessageKind.Request, 42, "test.method", IpcJson.ToElement(new { Value = 7, Name = "x" }));

        await MessageFraming.WriteAsync(stream, original);
        stream.Position = 0;
        IpcMessage? read = await MessageFraming.ReadAsync(stream);

        Assert.NotNull(read);
        Assert.Equal(MessageKind.Request, read.Kind);
        Assert.Equal(42, read.Id);
        Assert.Equal("test.method", read.Method);
        Assert.Equal(7, read.Payload!.Value.GetProperty("value").GetInt32());
        Assert.Null(read.Error);
    }

    [Fact]
    public async Task Reads_several_messages_in_sequence_then_null_at_end()
    {
        var stream = new MemoryStream();
        for (int i = 1; i <= 3; i++)
            await MessageFraming.WriteAsync(stream, new IpcMessage(MessageKind.Event, i, "e"));
        stream.Position = 0;

        for (int i = 1; i <= 3; i++)
            Assert.Equal(i, (await MessageFraming.ReadAsync(stream))!.Id);
        Assert.Null(await MessageFraming.ReadAsync(stream));
    }

    [Fact]
    public async Task Empty_stream_returns_null()
    {
        Assert.Null(await MessageFraming.ReadAsync(new MemoryStream()));
    }

    [Fact]
    public async Task Truncated_body_throws()
    {
        var stream = new MemoryStream();
        await MessageFraming.WriteAsync(stream, new IpcMessage(MessageKind.Request, 1, "m"));
        var truncated = new MemoryStream(stream.ToArray()[..^3]);

        await Assert.ThrowsAsync<EndOfStreamException>(() => MessageFraming.ReadAsync(truncated));
    }

    [Fact]
    public async Task Truncated_header_throws()
    {
        await Assert.ThrowsAsync<EndOfStreamException>(() => MessageFraming.ReadAsync(new MemoryStream([1, 0])));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(MessageFraming.MaxMessageBytes + 1)]
    public async Task Invalid_length_prefix_is_rejected(int length)
    {
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, length);

        await Assert.ThrowsAsync<InvalidDataException>(() => MessageFraming.ReadAsync(new MemoryStream(header)));
    }

    [Fact]
    public async Task Garbage_body_throws_json_exception()
    {
        byte[] frame = [3, 0, 0, 0, (byte)'a', (byte)'b', (byte)'c'];

        await Assert.ThrowsAnyAsync<System.Text.Json.JsonException>(() => MessageFraming.ReadAsync(new MemoryStream(frame)));
    }

    [Fact]
    public void Enums_serialize_as_strings()
    {
        var element = IpcJson.ToElement(new IpcMessage(MessageKind.Response, 1, "m"))!.Value;
        Assert.Equal("Response", element.GetProperty("kind").GetString());
    }
}
