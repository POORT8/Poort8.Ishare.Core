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
    [property: JsonPropertyName("target")] EnvironmentTarget Target,
    [property: JsonPropertyName("policies")] IReadOnlyList<Policy> Policies
);

public record EnvironmentTarget(
    [property: JsonPropertyName("environment")] Environment Environment
);

public record Environment(
    [property: JsonPropertyName("licenses")] IReadOnlyList<string> Licenses
);

public record Policy(
    [property: JsonPropertyName("target")] ResourceTarget Target,
    [property: JsonPropertyName("rules")] IReadOnlyList<Rule> Rules
);

public record ResourceTarget(
    [property: JsonPropertyName("resource")] Resource Resource,
    [property: JsonPropertyName("actions")] IReadOnlyList<string> Actions
);

public record Resource(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("identifiers")] IReadOnlyList<string> Identifiers,
    [property: JsonPropertyName("attributes")] IReadOnlyList<string> Attributes
);

public record Rule(
    [property: JsonPropertyName("effect")] string Effect
);

public record DelegationResponse(
    [property: JsonPropertyName("delegation_token")] string DelegationToken
);
