﻿namespace Poort8.Ishare.Core;

public interface IAuthenticationService
{
    string CreateAccessToken(string audience);
    string CreateClientAssertion(string audience, int expSeconds = 30);
    void ValidateAccessToken(string validIssuer, string accessToken);
    void ValidateToken(string validIssuer, string token, int expSeconds = 30);
}