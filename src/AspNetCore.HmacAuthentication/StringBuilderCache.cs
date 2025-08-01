using System.Text;

namespace AspNetCore.HmacAuthentication;

internal static class StringBuilderCache
{
    [ThreadStatic]
    private static StringBuilder? _cachedInstance;

    public static StringBuilder Acquire(int capacity = 256)
    {
        var builder = _cachedInstance;
        if (builder == null || builder.Capacity < capacity)
            return new StringBuilder(capacity);

        _cachedInstance = null;

        return builder.Clear();
    }

    public static string ToString(StringBuilder builder)
    {
        string result = builder.ToString();

        Release(builder);

        return result;
    }

    public static void Release(StringBuilder builder)
    {
        // allow reusing StringBuilder instances with a capacity of 4096 or less
        if (builder.Capacity <= 4096)
            _cachedInstance = builder;
    }
}
