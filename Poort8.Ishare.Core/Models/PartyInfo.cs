using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public record PartyInfo(
    [property: JsonPropertyName("party_id")] string PartyId,
    [property: JsonPropertyName("party_name")] string PartyName,
    [property: JsonPropertyName("capability_url")] string CapabilityUrl,
    [property: JsonPropertyName("registrar_id")] string RegistrarId,
    [property: JsonPropertyName("adherence")] Adherence Adherence,
    [property: JsonPropertyName("additional_info")] AdditionalInfo AdditionalInfo,
    [property: JsonPropertyName("agreements")] IReadOnlyList<Agreement> Agreements,
    [property: JsonPropertyName("certificates")] IReadOnlyList<Certificate> Certificates,
    [property: JsonPropertyName("certifications")] IReadOnlyList<Certification> Certifications, //TODO: SchemeOwner only
    [property: JsonPropertyName("roles")] IReadOnlyList<RoleObject> Roles,
    [property: JsonPropertyName("authregistery")] IReadOnlyList<Authregistery> Authregistery,
    [property: JsonPropertyName("spor")] Spor Spor
);

public record Adherence(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("start_date")] DateTime StartDate,
    [property: JsonPropertyName("end_date")] DateTime EndDate
);

public record AdditionalInfo(
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("logo")] string Logo,
    [property: JsonPropertyName("website")] string Website,
    [property: JsonPropertyName("company_phone")] string CompanyPhone,
    [property: JsonPropertyName("company_email")] string CompanyEmail,
    [property: JsonPropertyName("publicly_publishable")] string PubliclyPublishable,
    [property: JsonPropertyName("countriesOfOperation")] IReadOnlyList<object> CountriesOfOperation,
    [property: JsonPropertyName("sectorIndustry")] IReadOnlyList<object> SectorIndustry,
    [property: JsonPropertyName("tags")] string Tags
);

public record Agreement(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("sign_date")] DateTime SignDate,
    [property: JsonPropertyName("expiry_date")] DateTime ExpiryDate,
    [property: JsonPropertyName("hash_file")] string HashFile,
    [property: JsonPropertyName("framework")] string Framework,
    [property: JsonPropertyName("dataspace_id")] string DataspaceId,
    [property: JsonPropertyName("dataspace_title")] string DataspaceTitle,
    [property: JsonPropertyName("complaiancy_verified")] string ComplaiancyVerified
);

public record Certificate(
    [property: JsonPropertyName("subject_name")] string SubjectName,
    [property: JsonPropertyName("certificate_type")] string CertificateType,
    [property: JsonPropertyName("enabled_from")] DateTime EnabledFrom,
    [property: JsonPropertyName("x5c")] string X5c,
    [property: JsonPropertyName("x5t#s256")] string X5tS256
);

//TODO: SchemeOwner only
public record Certification(
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("start_date")] DateTime StartDate,
    [property: JsonPropertyName("end_date")] DateTime EndDate,
    [property: JsonPropertyName("loa")] int Loa
);

public record RoleObject(
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("start_date")] DateTime StartDate,
    [property: JsonPropertyName("end_date")] DateTime EndDate,
    [property: JsonPropertyName("loa")] string Loa,
    [property: JsonPropertyName("complaiancy_verified")] string ComplaiancyVerified,
    [property: JsonPropertyName("legal_adherence")] string LegalAdherence
);

public record Authregistery(
    [property: JsonPropertyName("authorizationRegistryName")] string AuthorizationRegistryName,
    [property: JsonPropertyName("authorizationRegistryID")] string AuthorizationRegistryID,
    [property: JsonPropertyName("authorizationRegistryUrl")] string AuthorizationRegistryUrl,
    [property: JsonPropertyName("dataspaceID")] string DataspaceID,
    [property: JsonPropertyName("dataspaceName")] string DataspaceName
);

public record Spor(
    [property: JsonPropertyName("signed_request")] string SignedRequest
);
