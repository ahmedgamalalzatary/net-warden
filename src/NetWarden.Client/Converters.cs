using System.Globalization;
using System.Windows.Data;

namespace NetWarden.Client;

/// <summary>Country code to its bundled flag image; nothing for a code without one.</summary>
public sealed class FlagImageConverter : System.Windows.Data.IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        if (value is not string { Length: 2 } code)
            return null;
        var uri = new Uri($"pack://application:,,,/NetWarden.Client;component/Assets/Flags/{code}.png");
        try
        {
            return System.Windows.Application.GetResourceStream(uri) is null ? null : new System.Windows.Media.Imaging.BitmapImage(uri);
        }
        catch (System.IO.IOException)
        {
            return null;
        }
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Filter function "is" (true) / "is not" (false) to combo box index 0 / 1.</summary>
public sealed class MatchToIndexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is false ? 1 : 0;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is not 1;
}

/// <summary>Binds radio buttons to an enum: checked when the value equals the parameter.</summary>
public sealed class EnumToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        Equals(value, parameter);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? parameter : Binding.DoNothing;
}
