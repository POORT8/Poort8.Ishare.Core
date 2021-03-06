using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Poort8.Ishare.Core.Tests;

[TestClass]
public class PolicyEnforcementPointTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    private static Mock<ILogger<PolicyEnforcementPoint>> LoggerMock;
    private static Mock<IAuthenticationService> AuthenticationServiceMock;
    private static readonly string _authorizationRegistryId = "EU.EORI.NL888888881";
    private static readonly string _delegationToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlEdlRDQ0FxV2dBd0lCQWdJSUt5WFRoTVFGM1hJd0RRWUpLb1pJaHZjTkFRRUxCUUF3Y1RGR01FUUdBMVVFQXd3OVZFVlRWQ0JwVTBoQlVrVWdSbTkxYm1SaGRHbHZiaUJRUzBsdmRtVnlhR1ZwWkNCUGNtZGhibWx6WVhScFpTQlRaWEoyWlhJZ1EwRWdMU0JITXpFYU1CZ0dBMVVFQ2d3UmFWTklRVkpGSUVadmRXNWtZWFJwYjI0eEN6QUpCZ05WQkFZVEFrNU1NQjRYRFRJd01UQXlPREV3TURReU9Wb1hEVEkxTVRBeU56RXdNRFF5T1Zvd1dURVZNQk1HQTFVRUF3d01VRzl2Y25RZ09DQkNMbFl1TVJ3d0dnWURWUVFGRXhORlZTNUZUMUpKTGs1TU9EZzRPRGc0T0RneE1SVXdFd1lEVlFRS0RBeFFiMjl5ZENBNElFSXVWaTR4Q3pBSkJnTlZCQVlUQWs1TU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcHFWcGRTZ0djd0JBQXJsbUxTVzZrR1JMK29XbENOVEd1Zmg5dmZxSlU3ZmtzOEFGQ01MS0FVZTI2VGdPWkpXRFRDYU5KbU1ZRmI3Yk1ReFNDM2JmbERiUmsxbDlDcC9NcUhnZE1zUkVMY3pUWWdhdXZoTEMvOVBIcnRDRitQUmw2VjQvR2h1dDJ6SDkxbzJPSkpCalpmYlgrbzhxdHhKcnFOUENjYVhjVEM2cVR2cUtFNGZKaHFHOGlXVFUrTmFndDFVT2RKdTFQNHBmOVMwWTFWNnY0VDNYLzNiM1VvWDFpWi9ibzRFVmJsQmU5UStRbUJGUGxWRFJ4YTBHS2laTkg4SkdnRmpUSVh5Y2s1b2pMc3JKWVI5M1Y3Wk43TzNUbnR5dDMxZVhsUEpKZ1NYdyszM2FvZkJZeG1pUWRqRzVkdXYvTHdOZHh0WGc2KzU5bnA1NnFRSURBUUFCbzNFd2J6QWZCZ05WSFNNRUdEQVdnQlJXdytSMDVPUkZOZjRnV3dJVzdMZksyd2tRY0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFnWUlLd1lCQlFVSEF3RXdIUVlEVlIwT0JCWUVGQmhuek1PWEpHa2gwYmdpQnlxdFhDVDdMdTM2TUE0R0ExVWREd0VCL3dRRUF3SUZvREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBbnRlK0JwVTI3VGRjZFRSNGV3OUJPSi83UEFEaWdyZmQ0a3cvcmRIR0FEdlpxTU44K3l6cXJ2aWVYeVUwd0NMQTFic29wa0QxQTU4MWRSWmxFQnVSdnppRmJzaVJodjdnc3REYWg1aUpNQVh5NFRlbkwxRURKUFQwSXdiUlRFR0RjSkZ4WHFFUEFIMUl1dStla3JWMGF1N25ISGJWOHdYM1d5OWZBV3F3THU5eTljcFZxS3VhSThaK203TnNoTGJ4WHU0cml1MWFNTmg4cGVlSTRnMEdWT2pFY05BTEZFQm5zekVBRlNKMVBha0IwMzNGN0l4S3JEUEZwdlVWYjllelRhcWhXcTE4OWxlU3JOS2FlNlpJUE9kL25QT1IrNTd4Si9lejc3VzhaTWozOUx1eVVwK0dLZjd2dm50RVZ5UWZKRUw2WFZFZDlRejh1ak5reHJuKzRBPT0iLCJNSUlEeFRDQ0FxMmdBd0lCQWdJSU41YlBnZkpFVWJRd0RRWUpLb1pJaHZjTkFRRUxCUUF3YnpGQU1ENEdBMVVFQXd3M1ZFVlRWQ0JUZEdGaGRDQmtaWElnVG1Wa1pYSnNZVzVrWlc0Z1QzSm5ZVzVwYzJGMGFXVWdVMlZ5ZG1salpYTWdRMEVnTFNCSE16RWVNQndHQTFVRUNnd1ZVM1JoWVhRZ1pHVnlJRTVsWkdWeWJHRnVaR1Z1TVFzd0NRWURWUVFHRXdKT1REQWVGdzB4T1RBeU1qQXhOVE0yTXpkYUZ3MHpPVEF5TVRVeE5UTXhNVEJhTUhFeFJqQkVCZ05WQkFNTVBWUkZVMVFnYVZOSVFWSkZJRVp2ZFc1a1lYUnBiMjRnVUV0SmIzWmxjbWhsYVdRZ1QzSm5ZVzVwYzJGMGFXVWdVMlZ5ZG1WeUlFTkJJQzBnUnpNeEdqQVlCZ05WQkFvTUVXbFRTRUZTUlNCR2IzVnVaR0YwYVc5dU1Rc3dDUVlEVlFRR0V3Sk9URENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMckt0dVJuYVM3aEt0WVpXM3U4N1VpYjFCcnZKU1N1TkwzM3Q0c3cxeVBVQ0RzUWVvNVVrSEhKREl4UEpuUVp2RC83UDVkd1JlekVhU2RVZ2JvQnpzaXdGMFkwbHNNWFZKU043MzQvV0JtUm1PcWpETDQzREpGREUvWG1raVdmZFdJMGIzd0dkZEgzS0ZIaFgyU2hzUllKNnIyZnZxcnNoRXREWGNCREF3RHR4UVhvQjVpeHMySWRkYXpzd0Ftc3VVbHp0UlNtTWliWmdZTXJobWFIU1JBTVFab0grUG9FODNjQlNXYXB4KzVUOE1lRjhyU2srVlhpQ25BSmtHZTdidE9ZOWZPcVNTNEgyKzFkbHdvZUlpYllFREthNndRNnluSERZekxCV2NTSENDa2NpNHRJTEU0cjJhQmZoYkFTaTh3NXBVenQycytmcGYwOWZ1L3ozZlVDQXdFQUFhTmpNR0V3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFmQmdOVkhTTUVHREFXZ0JTWHVFTzBxVlp0ajBaREdOTndYT1BDK0NQcjNUQWRCZ05WSFE0RUZnUVVWc1BrZE9Ua1JUWCtJRnNDRnV5M3l0c0pFSEF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNoYVRkYW9wems3dzBReHMyT05rR04zWlhXbGxWeUxlZkpEdU1sMGo4eDdZNmwvZ0M4bWVobXNGeTZZK2lJZk1kaTV6ZG1KY0RJZUZEUW5RRzY4SGdDY09lM01lbEZwcUorMUd1Z3U2WmFqRHFMdVgvWXA0VG9Hd1pWR2dRRUw4K284cHdzbEloTENFZ25Vb0hzdTV2V09Hams3ak9YelJxYWpGSnEyOGN5bG10ZENsbVg2a1R1RkFuWWRjNFh4MVJSbDJRZjRpaEZtTXNKT1RXcFRMSFJ3Y0tudDFyTjNzaWMycnpYNVh6VnpUa21NSXk2dVF2d2s5V2R6blNYTVZ3ZzNrb2JTUUJvc0VTWDg3SFZoWEhvS0pwWSt6VldnQlpSbTdPbkFlOUNHY0xmM1AzNHRXR0FBZzEwWTRLdlFrbi9QTDVYOGxIcXJGMkZvcUVpZFZIYyIsIk1JSUR1RENDQXFDZ0F3SUJBZ0lJWHBocm5XYmQzSmt3RFFZSktvWklodmNOQVFFTEJRQXdaREV3TUM0R0ExVUVBd3duVkVWVFZDQlRkR0ZoZENCa1pYSWdUbVZrWlhKc1lXNWtaVzRnVW05dmRDQkRRU0F0SUVjek1TTXdJUVlEVlFRS0RCcFVSVk5VSUZOMFlXRjBJR1JsY2lCT1pXUmxjbXhoYm1SbGJqRUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1Ua3dNakl3TVRVek1qUTVXaGNOTXprd01qRTFNVFV6TVRFd1dqQnZNVUF3UGdZRFZRUURERGRVUlZOVUlGTjBZV0YwSUdSbGNpQk9aV1JsY214aGJtUmxiaUJQY21kaGJtbHpZWFJwWlNCVFpYSjJhV05sY3lCRFFTQXRJRWN6TVI0d0hBWURWUVFLREJWVGRHRmhkQ0JrWlhJZ1RtVmtaWEpzWVc1a1pXNHhDekFKQmdOVkJBWVRBazVNTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwREtzK3Btd1dLUDVmUkxobTcvTmEwdndQem9NVDJkSHVzeVJhelpzRlNuZUpEeGFIazJMekpLUkY5bnIrdXhKUEZ3RWdxaW8xbmhpSktDS0kwYW94WjhsRTV6V01hWTdzRjlzZFdVbFN3bHd5ZkYxZ2xqdnpCNmVIeGppUXQyY3pNNmMybTdsZzlUcDNLRk9nZXVOQXE3bnVNbkVFNzJpeDJOcHoydVlubitIOEZ2WVQrSGlKcFN4aXV6WkZHZFJSdXZjYmcrWlM4bkw2bjNFY0RjWGFFZGozaHNiNFpRd0p6Y05qZmlycUFZUFBTallrb2xWbE5kZytMbTF1VXhHcE1qMGFFdkJWZ3NtWnJXZWRMZC9EdWdmT2crQWYvTjRvTUtWTmx1NFJXT0NvL1kvdzQ0UzlWa29VdkZidkttS0pFZDI5Y0lJQTBRaStvMGVCeCtZV3dJREFRQUJvMk13WVRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUI4R0ExVWRJd1FZTUJhQUZFS3JYU2NlRk9veTR4bWFuQWpSdUEzWWVaVmpNQjBHQTFVZERnUVdCQlNYdUVPMHFWWnRqMFpER05Od1hPUEMrQ1ByM1RBT0JnTlZIUThCQWY4RUJBTUNBWVl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUE4cGdiRmJjRXQ3V0ErWEtrajhrTERabWJwMitTaktVb2ZydVBTUFM0U3cvUkNmSm1sVEhBc2N6RDBNQXkya0d1ZW53c0h2OXdjWlFoWldQL2Q3cG9YK2hidUlWRlc0aGR4dmh4amdVbW1VeFdzbHVFSVcycU8weFRoTDFyZkVtNlVDSEhlaGpTUWpSZzJpUkNvc01ZUzJ3SzJnVWNOOVhqUThxeDk4WHVQSFNSYUpOa2t2S3pSZU5OUjRMSXhReWNiRGsvek9Xa2gwdFhSZ2ZTZ2VRNndyN2RaR0QyQzlrT0hYSmIzZFVnVjBNbFEyM2lrU2YvVDd4VkJ6VlYrVGpxTDQyRFhsa3BCVGxuT0c3SGg5KzA1d001Tmp5Z2NmQTM2R3QyS21GVUl6dHJXWkdrSnhPc1U1UTdaYVdZNFIxUUhPSmRzMVd5LzdMU253d1hqODNGST0iLCJNSUlEclRDQ0FwV2dBd0lCQWdJSUVUenU1S3BIWmN3d0RRWUpLb1pJaHZjTkFRRUxCUUF3WkRFd01DNEdBMVVFQXd3blZFVlRWQ0JUZEdGaGRDQmtaWElnVG1Wa1pYSnNZVzVrWlc0Z1VtOXZkQ0JEUVNBdElFY3pNU013SVFZRFZRUUtEQnBVUlZOVUlGTjBZV0YwSUdSbGNpQk9aV1JsY214aGJtUmxiakVMTUFrR0ExVUVCaE1DVGt3d0hoY05NVGt3TWpJd01UVXpNVEV3V2hjTk16a3dNakUxTVRVek1URXdXakJrTVRBd0xnWURWUVFERENkVVJWTlVJRk4wWVdGMElHUmxjaUJPWldSbGNteGhibVJsYmlCU2IyOTBJRU5CSUMwZ1J6TXhJekFoQmdOVkJBb01HbFJGVTFRZ1UzUmhZWFFnWkdWeUlFNWxaR1Z5YkdGdVpHVnVNUXN3Q1FZRFZRUUdFd0pPVERDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTUpBWU9wOWxPL2pkaGI2ekVyUnVLVjhLSk9WM0RNTE9lUHloL2RlWXdrd2FLYnk0ZWNOU01ZTzlRL0VCVHN1VFlSbm4wTXFFQVhxSDN5aTlKeUc4UGdaSlhmS2dPcm4xM2d3bitWVGJDalVZeEVKemQ0bmQrWDh5YTRtbmxsc0N1MEl3WG5qNDBzQnNFZ2IyTGZra2NHVGxEMjg1QlNPS3hESTg5SmFhbDlXNTd5aEs5RWFST2ZpNHhTdHB6UVhYTUdpbUVBQlRNWXJveHFxeGF5VmRyMzFaY1B3aGthZzZHeXk1bFBTNm9NVkdWSVdTNnZYZzB4UEtYYVRRQmUrZFY3b1pLd0pIQ3hpRERtcDVkaS8xbG0ydDYyMytiUjVKMGtrc3FicTlKdW15YW5kMDBKSXRVWEUxRnpMNzlYN0I2cjBDbGdsR1hmMWJrT3lnRVY1eEFzQ0F3RUFBYU5qTUdFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZkJnTlZIU01FR0RBV2dCUkNxMTBuSGhUcU11TVptcHdJMGJnTjJIbVZZekFkQmdOVkhRNEVGZ1FVUXF0ZEp4NFU2akxqR1pxY0NORzREZGg1bFdNd0RnWURWUjBQQVFIL0JBUURBZ0dHTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFDblNvZm81MVY0ZGdVNW1ETnZwQUpYeDJTZFFnQ1JxeTdsVGVHU2MzNDNqNDNxaFhLclRKdldXTGdId2lPMVBuUzZhNDc2c09DajMzcG02UkFEWmdnV3l3ZW9LZ3VHRngwT003L0ZTSDJONWY2MXFIZnFoTndpZEJ2RHEyb0hTSmFyTHZOL1VoRTlyREdHWFAyY05SM2RObnJQZUJHNnZUcFc5OGdmWUJWWjIwdlJzRTU5bGQ2MElBTlRSN1oxelN3ZE5tRkRpemhrck00TloxWlBCTjMwSW5aY3Vyd2JWbzVSN2N4bWp5cFZ1RFlhRkVYWVY1QWsyTnhsck0yZ0dSNFhlVWpVVHFtQzhRZFJVZVViTDJMV3lzeUFkdTlteks0VW1PMGVBakhvWVE1aUJRQmlXcFdqMnlhcWdMTG8zM3lJd1ZwU3BoK3F3NUwweHJ5dk9Sc0MiXX0.eyJzdWIiOiJFVS5FT1JJLk5MODg4ODg4ODgxIiwianRpIjoiNGRkZWM0NjMtMTJhZC00YWMzLWJmYzItYTQ0MDliOWVlMDBiIiwicGxheWJvb2siOiJEVlUiLCJwbGF5Ym9va1ZlcnNpb24iOiIyLjAuMCIsImRlbGVnYXRpb25FdmlkZW5jZSI6eyJub3RCZWZvcmUiOjE2NTA0NTU3MTUsIm5vdE9uT3JBZnRlciI6MTY4MTk0ODgwMCwicG9saWN5SXNzdWVyIjoiRVUuRU9SSS5OTDg4ODg4ODg4MSIsInRhcmdldCI6eyJhY2Nlc3NTdWJqZWN0IjoiRVUuRU9SSS5OTDg4ODg4ODg4MiJ9LCJwb2xpY3lTZXRzIjpbeyJtYXhEZWxlZ2F0aW9uRGVwdGgiOjAsInRhcmdldCI6eyJlbnZpcm9ubWVudCI6eyJsaWNlbnNlcyI6WyJpU0hBUkUuOTk5OSJdfX0sInBvbGljaWVzIjpbeyJ0YXJnZXQiOnsicmVzb3VyY2UiOnsidHlwZSI6IlA0IFBvcnRhbCIsImlkZW50aWZpZXJzIjpbIkVBTnRlc3QxMjMiXSwiYXR0cmlidXRlcyI6WyJJbnRlcnZhbHN0YW5kZW4iXX0sImFjdGlvbnMiOlsiV2Vya2VsaWprIGVuZXJnaWV2ZXJicnVpay5SZWFkIl0sImVudmlyb25tZW50Ijp7InNlcnZpY2VQcm92aWRlcnMiOlsiRVUuRU9SSS5OTDg4ODg4ODg4MSJdfX0sInJ1bGVzIjpbeyJlZmZlY3QiOiJQZXJtaXQifV19XX1dfSwibmJmIjoxNjUwNTQ3NzAyLCJleHAiOjE2NTA1NDc3MzIsImlhdCI6MTY1MDU0NzcwMiwiaXNzIjoiRVUuRU9SSS5OTDg4ODg4ODg4MSIsImF1ZCI6IkVVLkVPUkkuTkw4ODg4ODg4ODIifQ.GJaJdhYRCDiBXxddfwW1GPb3oOfLPwcLiE-SDx1MP_BM07oiKclAnse95J00seJmetSTxaq7IRS0hFT54sNFNJ-2ijVZEv81AkYpB9fhZbpls22Q6uGewyz0L54nXJJWkWHgE2anVplYaqJi_ipoaZw9Bq6TWQd5RbtCuq1h0MMUW0rsZeJXF38WMwyJUVXSHwx_lkE__6F9wTgbTDQp_--Kuo52O2znhNBkmpAMI9hfFgizihyiwh0T9-0TeZyz1jkYgkvQDOXRfu_f3CgSJLkSodL4fMmmfPiFsp5n0FtqyMpgf4Cd7dXTBIcGJ_yMFz8p3nmMh2LUkErTA_T-HA";
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

    [ClassInitialize]
    public static void ClassInitialize(TestContext testContext)
    {
        LoggerMock = new Mock<ILogger<PolicyEnforcementPoint>>();

        AuthenticationServiceMock = new Mock<IAuthenticationService>();
        AuthenticationServiceMock.
            Setup(x => x.ValidateToken(_authorizationRegistryId, _delegationToken, 30, true, false));
    }

    [TestMethod]
    public void TestVerifyDelegationEvidencePermit()
    {
        var policyEnforcementPoint = new PolicyEnforcementPoint(LoggerMock.Object, AuthenticationServiceMock.Object);

        var permit = policyEnforcementPoint.VerifyDelegationTokenPermit(
            _authorizationRegistryId,
            _delegationToken,
            "DVU",
            "2.0.0",
            "EU.EORI.NL888888882",
            "P4 Portal",
            "EANtest123");
        Assert.IsTrue(permit);
    }

    [TestMethod]
    public void TestVerifyDelegationEvidencePermitFails()
    {
        var policyEnforcementPoint = new PolicyEnforcementPoint(LoggerMock.Object, AuthenticationServiceMock.Object);

        var permit = policyEnforcementPoint.VerifyDelegationTokenPermit(
            _authorizationRegistryId,
            _delegationToken,
            "invalid",
            "2.0.0",
            "EU.EORI.NL888888882",
            "P4 Portal",
            "EANtest123");
        Assert.IsFalse(permit);

        permit = policyEnforcementPoint.VerifyDelegationTokenPermit(
            _authorizationRegistryId,
            _delegationToken,
            "DVU",
            "3.0.0",
            "EU.EORI.NL888888882",
            "P4 Portal",
            "EANtest123");
        Assert.IsFalse(permit);

        permit = policyEnforcementPoint.VerifyDelegationTokenPermit(
            _authorizationRegistryId,
            _delegationToken,
            "DVU",
            "2.0.0",
            "invalid",
            "P4 Portal",
            "EANtest123");
        Assert.IsFalse(permit);

        permit = policyEnforcementPoint.VerifyDelegationTokenPermit(
            _authorizationRegistryId,
            _delegationToken,
            "DVU",
            "2.0.0",
            "EU.EORI.NL888888882",
            "invalid",
            "EANtest123");
        Assert.IsFalse(permit);

        permit = policyEnforcementPoint.VerifyDelegationTokenPermit(
            _authorizationRegistryId,
            _delegationToken,
            "DVU",
            "2.0.0",
            "EU.EORI.NL888888882",
            "P4 Portal",
            "invalid");
        Assert.IsFalse(permit);
    }
}
