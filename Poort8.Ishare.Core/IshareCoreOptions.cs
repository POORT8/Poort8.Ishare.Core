using System.ComponentModel.DataAnnotations;

namespace Poort8.Ishare.Core;

public class IshareCoreOptions
{
    [Required]
    public required string ClientId { get; set; }
    [Required]
    public required string AuthorizationRegistryId { get; set; }
    [Required]
    public required string AuthorizationRegistryUrl { get; set; }
    [Required]
    public required string SatelliteId { get; set; }
    [Required]
    public required string SatelliteUrl { get; set; }
    public string? AzureKeyVaultUrl { get; set; }
    public string? CertificateName { get; set; }
    public string? Certificate { get; set; }
    public string? CertificatePassword { get; set; }
    public string? CertificateChain { get; set; }
    public string? CertificateChainPassword { get; set; }
}
