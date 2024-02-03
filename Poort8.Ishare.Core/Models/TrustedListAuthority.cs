using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public record TrustedListAuthority(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("certificate_fingerprint")] string CertificateFingerprint,
    [property: JsonPropertyName("validity")] string Validity,
    [property: JsonPropertyName("status")] string Status
);
