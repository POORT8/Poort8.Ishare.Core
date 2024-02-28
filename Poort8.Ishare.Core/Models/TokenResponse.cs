using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn
);
