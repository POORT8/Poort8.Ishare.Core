using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public class PartyInfo
{
    [JsonPropertyName("party_id")]
    public string? PartyId { get; set; }

    [JsonPropertyName("party_name")]
    public string? PartyName { get; set; }

    [JsonPropertyName("adherence")]
    public AdherenceObject? Adherence { get; set; }

    [JsonPropertyName("certifications")]
    public List<Certification>? Certifications { get; set; } //TODO: Remove when migrated to Satellite

    [JsonPropertyName("capability_url")]
    public string? CapabilityUrl { get; set; }

    [JsonPropertyName("registrar_id")]
    public string? RegistrarId { get; set; }

    [JsonPropertyName("spor")]
    public SporObject? Spor { get; set; }

    [JsonPropertyName("additional_info")]
    public AdditionalInfoObject? AdditionalInfo { get; set; }

    [JsonPropertyName("agreements")]
    public List<Agreement>? Agreements { get; set; }

    [JsonPropertyName("certificates")]
    public List<Certificate>? Certificates { get; set; }

    [JsonPropertyName("roles")]
    public List<RoleObject>? Roles { get; set; }

    [JsonPropertyName("auth_registries")]
    public List<AuthRegistry>? AuthRegistries { get; set; }

    public class AdherenceObject
    {
        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("start_date")]
        public DateTime StartDate { get; set; }

        [JsonPropertyName("end_date")]
        public DateTime EndDate { get; set; }
    }

    public class Certification //TODO: Remove when migrated to Satellite
    {
        [JsonPropertyName("role")]
        public string? Role { get; set; }

        [JsonPropertyName("start_date")]
        public DateTime StartDate { get; set; }

        [JsonPropertyName("end_date")]
        public DateTime EndDate { get; set; }

        [JsonPropertyName("loa")]
        public int Loa { get; set; }
    }

    public class SporObject
    {
        [JsonPropertyName("signed_request")]
        public string? SignedRequest { get; set; }
    }

    public class AdditionalInfoObject
    {
        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("logo")]
        public string? Logo { get; set; }

        [JsonPropertyName("website")]
        public string? Website { get; set; }

        [JsonPropertyName("company_phone")]
        public string? CompanyPhone { get; set; }

        [JsonPropertyName("company_email")]
        public string? CompanyEmail { get; set; }

        [JsonPropertyName("publicly_publishable")]
        public string? PubliclyPublishable { get; set; }

        [JsonPropertyName("countriesOfOperation")]
        public List<object>? CountriesOfOperation { get; set; }

        [JsonPropertyName("sectorIndustry")]
        public List<object>? SectorIndustry { get; set; }

        [JsonPropertyName("tags")]
        public string? Tags { get; set; }
    }

    public class Agreement
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("sign_date")]
        public DateTime SignDate { get; set; }

        [JsonPropertyName("expiry_date")]
        public DateTime ExpiryDate { get; set; }

        [JsonPropertyName("hash_file")]
        public string? HashFile { get; set; }

        [JsonPropertyName("framework")]
        public string? Framework { get; set; }

        [JsonPropertyName("dataspace_id")]
        public string? DataspaceId { get; set; }

        [JsonPropertyName("dataspace_title")]
        public string? DataspaceTitle { get; set; }

        [JsonPropertyName("complaiancy_verified")]
        public string? ComplaiancyVerified { get; set; }
    }

    public class Certificate
    {
        [JsonPropertyName("subject_name")]
        public string? SubjectName { get; set; }

        [JsonPropertyName("certificate_type")]
        public string? CertificateType { get; set; }

        [JsonPropertyName("enabled_from")]
        public DateTime EnabledFrom { get; set; }

        [JsonPropertyName("x5c")]
        public string? X5c { get; set; }

        [JsonPropertyName("x5t#s256")]
        public string? X5tS256 { get; set; }
    }

    public class RoleObject
    {
        [JsonPropertyName("role")]
        public string? Role { get; set; }

        [JsonPropertyName("start_date")]
        public DateTime StartDate { get; set; }

        [JsonPropertyName("end_date")]
        public DateTime EndDate { get; set; }

        [JsonPropertyName("loa")]
        public string? LOA { get; set; }

        [JsonPropertyName("complaiancy_verified")]
        public string? ComplaiancyVerified { get; set; }

        [JsonPropertyName("legal_adherence")]
        public string? LegalAdherence { get; set; }
    }

    public class AuthRegistry
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("url")]
        public string? Url { get; set; }

        [JsonPropertyName("dataspace_id")]
        public string? DataspaceId { get; set; }

        [JsonPropertyName("dataspace_name")]
        public string? DataspaceName { get; set; }
    }
}
