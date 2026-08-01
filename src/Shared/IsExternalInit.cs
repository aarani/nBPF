namespace System.Runtime.CompilerServices;

/// <summary>
/// Polyfill so records and init-only properties compile on netstandard2.0, which predates
/// this type. Linked into each netstandard2.0 project — see DESIGN.md §6.6 for why those
/// projects cannot simply target net10.0 instead.
/// </summary>
internal static class IsExternalInit;
