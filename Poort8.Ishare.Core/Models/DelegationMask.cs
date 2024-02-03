using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public class DelegationMask
{
    [JsonPropertyName("delegationRequest")]
    public required DelegationRequestObject DelegationRequest { get; set; }

    public class DelegationRequestObject
    {
        [JsonPropertyName("policyIssuer")]
        public required string PolicyIssuer { get; set; }

        [JsonPropertyName("target")]
        public required TargetObject Target { get; set; }

        [JsonPropertyName("policySets")]
        public required List<PolicySet> PolicySets { get; set; }

        public class TargetObject
        {
            [JsonPropertyName("accessSubject")]
            public required string AccessSubject { get; set; }
        }

        public class PolicySet
        {
            [JsonPropertyName("policies")]
            public required List<Policy> Policies { get; set; }

            public class Policy
            {
                [JsonPropertyName("target")]
                public required TargetObject Target { get; set; }

                [JsonPropertyName("rules")]
                public required List<Rule> Rules { get; set; }

                public class TargetObject
                {
                    [JsonPropertyName("resource")]
                    public required ResourceObject Resource { get; set; }

                    [JsonPropertyName("actions")]
                    public required List<string> Actions { get; set; }

                    [JsonPropertyName("environment")]
                    public required EnvironmentObject Environment { get; set; }

                    public class ResourceObject
                    {
                        [JsonPropertyName("type")]
                        public required string Type { get; set; }

                        [JsonPropertyName("identifiers")]
                        public required List<string> Identifiers { get; set; }

                        [JsonPropertyName("attributes")]
                        public required List<string> Attributes { get; set; }
                    }

                    public class EnvironmentObject
                    {
                        [JsonPropertyName("serviceProviders")]
                        public required List<string> ServiceProviders { get; set; }
                    }
                }

                public class Rule
                {
                    [JsonPropertyName("effect")]
                    public required string Effect { get; set; }
                }
            }
        }
    }
}
