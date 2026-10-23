using System.Globalization;
using System.Windows.Data;

namespace NetWarden.Client;

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
