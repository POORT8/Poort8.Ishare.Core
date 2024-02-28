using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public record DelegationEvidence(
    [property: JsonPropertyName("notBefore")] int NotBefore,
    [property: JsonPropertyName("notOnOrAfter")] int NotOnOrAfter,
    [property: JsonPropertyName("policyIssuer")] string PolicyIssuer,
    [property: JsonPropertyName("target")] Target Target,
    [property: JsonPropertyName("policySets")] IReadOnlyList<PolicySet> PolicySets
);

public record Target(
    [property: JsonPropertyName("accessSubject")] string AccessSubject,
    [property: JsonPropertyName("environment")] Environment Environment,
    [property: JsonPropertyName("resource")] Resource Resource,
    [property: JsonPropertyName("actions")] IReadOnlyList<string> Actions
);

public record Environment(
    [property: JsonPropertyName("licenses")] IReadOnlyList<string> Licenses,
    [property: JsonPropertyName("serviceProviders")] IReadOnlyList<string> ServiceProviders
);

public record Resource(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("identifiers")] IReadOnlyList<string> Identifiers,
    [property: JsonPropertyName("attributes")] IReadOnlyList<string> Attributes
);

public record PolicySet(
    [property: JsonPropertyName("maxDelegationDepth")] int MaxDelegationDepth,
    [property: JsonPropertyName("target")] Target Target,
    [property: JsonPropertyName("policies")] IReadOnlyList<Policy> Policies
);

public record Policy(
    [property: JsonPropertyName("target")] Target Target,
    [property: JsonPropertyName("rules")] IReadOnlyList<Rule> Rules
);

public record Rule(
    [property: JsonPropertyName("effect")] string Effect
);
