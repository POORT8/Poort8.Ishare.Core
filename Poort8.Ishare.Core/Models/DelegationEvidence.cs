using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public record DelegationEvidence(
    [property: JsonPropertyName("notBefore")] long NotBefore,
    [property: JsonPropertyName("notOnOrAfter")] long NotOnOrAfter,
    [property: JsonPropertyName("policyIssuer")] string PolicyIssuer,
    [property: JsonPropertyName("target")] AccessSubjectTarget Target,
    [property: JsonPropertyName("policySets")] IReadOnlyList<PolicySet> PolicySets
);

public record AccessSubjectTarget(
    [property: JsonPropertyName("accessSubject")] string AccessSubject
);

public record PolicySet(
    [property: JsonPropertyName("maxDelegationDepth")] int MaxDelegationDepth,
    [property: JsonPropertyName("target")] LicenseTarget Target,
    [property: JsonPropertyName("policies")] IReadOnlyList<Policy> Policies
);

public record LicenseTarget(
    [property: JsonPropertyName("environment")] LicenseEnvironment Environment
);

public record LicenseEnvironment(
    [property: JsonPropertyName("licenses")] IReadOnlyList<string> Licenses
);

public record Policy(
    [property: JsonPropertyName("target")] ResourceTarget Target,
    [property: JsonPropertyName("rules")] IReadOnlyList<Rule> Rules
);

public record ResourceTarget(
    [property: JsonPropertyName("resource")] Resource Resource,
    [property: JsonPropertyName("environment")] ServiceProviderEnvironment Environment,
    [property: JsonPropertyName("actions")] IReadOnlyList<string> Actions
);

public record Resource(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("identifiers")] IReadOnlyList<string> Identifiers,
    [property: JsonPropertyName("attributes")] IReadOnlyList<string> Attributes
);

public record ServiceProviderEnvironment(
    [property: JsonPropertyName("serviceProviders")] IReadOnlyList<string> ServiceProviders
);

public record Rule(
    [property: JsonPropertyName("effect")] string Effect
);

public record DelegationResponse(
    [property: JsonPropertyName("delegation_token")] string DelegationToken
);
