namespace NetWarden.Tests;

internal static class TestPipes
{
    public static string NewName() => $"NetWarden.Test.{Guid.NewGuid():N}";
}

/// <summary>A temp directory deleted on dispose.</summary>
internal sealed class TempDir : IDisposable
{
    public string Path { get; } = Directory.CreateDirectory(
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "NetWarden.Tests", Guid.NewGuid().ToString("N"))).FullName;

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { }
    }
}
