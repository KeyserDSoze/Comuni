namespace Comuni.Business.Organizations;

/// <summary>
/// A code-owned catalog, NOT an authorization mechanism or a DB feature
/// flag. Only delivered backend modules can be configured by a municipality.
/// Planned modules have no endpoint/data model and must never be enabled.
/// </summary>
public sealed record ModuleCatalogItem(
    string Key, string Name, string Status, bool Enabled,
    bool Configurable, IReadOnlyList<string> DependsOn);

public static class ModuleCatalog
{
    public const string ProtocolKey = "protocol";

    private sealed record Definition(string Key, string Name, bool Implemented);

    // Stable, ordinal-key ordering for the API. Core itself is always on
    // and is never a tenant-toggleable service. Unimplemented domains are
    // intentionally not provisioned and have no guessed dependencies.
    private static readonly Definition[] Definitions =
    [
        new("administrative", "Amministrativo", false),
        new("archive", "Archivio documentale", false),
        new("cemetery", "Cimiteriale", false),
        new("demographics", "Demografico", false),
        new("finance", "Finanziario", false),
        new("local-police", "Polizia locale", false),
        new("personnel", "Personale", false),
        new(ProtocolKey, "Protocollo", true),
        new("public-works", "Lavori pubblici", false),
        new("taxes", "Tributi", false),
        new("urban-planning", "Urbanistica ed edilizia", false),
        new("utilities", "Utenze", false),
    ];

    public static bool IsImplemented(string key) =>
        string.Equals(key, ProtocolKey, StringComparison.Ordinal);

    public static IReadOnlyList<ModuleCatalogItem> Describe(
        IReadOnlyList<ModuleState> configured)
    {
        // The store is already tenant-scoped under signed RLS and filters
        // installed code modules. A rogue future flag is never authoritative.
        var protocol = configured.SingleOrDefault(x => x.Key == ProtocolKey);
        return Definitions.Select(definition =>
            new ModuleCatalogItem(
                definition.Key, definition.Name,
                definition.Implemented ? "available" : "planned",
                definition.Implemented && protocol?.Enabled == true,
                definition.Implemented && protocol is not null,
                Array.Empty<string>())).ToArray();
    }
}
