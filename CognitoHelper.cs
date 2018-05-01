using Amazon;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Amazon.CognitoIdentity.Model;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using ThirdParty.BouncyCastle.Math;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Configuration;

// Required for the GetS3BucketsAsync example
//using Amazon.S3;
//using Amazon.S3.Model;

namespace CognitoApi
{
    public class CognitoHelper
    {
        IConfiguration iconfiguration;
        private string POOL_ID = "";
        private string CLIENTAPP_ID = "";
        private string FED_POOL_ID = "";
        private string REGION = "";

        private AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), RegionEndpoint.USEast1);
        private static CognitoUserSession cognitoUserSession;

        public CognitoHelper(IConfiguration configuration)
        {
            iconfiguration = configuration;
            POOL_ID = iconfiguration.GetSection("AWSCogntio").GetSection("PoolId").Value;
            CLIENTAPP_ID = iconfiguration.GetSection("AWSCogntio").GetSection("CLIENTAPPID").Value;
            FED_POOL_ID = iconfiguration.GetSection("AWSCogntio").GetSection("FEDPOOLID").Value;
            REGION = iconfiguration.GetSection("AWSCogntio").GetSection("REGION").Value;
        }

        public async Task<RequestResult> SignUpUser(User user)
        {
            RequestResult result = new RequestResult();
            SignUpRequest signUpRequest = new SignUpRequest()
            {
                ClientId = CLIENTAPP_ID,
                Password = user.Password,
                Username = user.Email
            };

            AttributeType attributeType = new AttributeType();
            attributeType = new AttributeType();
            attributeType.Name = "custom:firstname";
            attributeType.Value = user.FirstName;
            signUpRequest.UserAttributes.Add(attributeType);

            attributeType = new AttributeType();
            attributeType.Name = "custom:lastname";
            attributeType.Value = user.LastName;
            signUpRequest.UserAttributes.Add(attributeType);

            attributeType = new AttributeType();
            attributeType.Name = "custom:userid";
            attributeType.Value = Guid.NewGuid().ToString();
            signUpRequest.UserAttributes.Add(attributeType);


            try
            {
                SignUpResponse response = await provider.SignUpAsync(signUpRequest);
                result.Status = true;
                result.Message = "User Registerd Successfully!";

            }
            catch (Exception e)
            {
                result.Status = false;
                result.Message = e.Message;
            }
            return result;

        }
        public async Task<RequestResult> VerifyAccessCode(User user)
        {
            RequestResult result = new RequestResult();
            ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest();
            confirmSignUpRequest.Username = user.Email;
            confirmSignUpRequest.ConfirmationCode = user.Code;
            confirmSignUpRequest.ClientId = CLIENTAPP_ID;
            try
            {
                ConfirmSignUpResponse confirmSignUpResult = await provider.ConfirmSignUpAsync(confirmSignUpRequest);
                Console.WriteLine(confirmSignUpResult.ToString());
                result.Status = true;
                result.Message = "User Verified Successfully. Please Sign In.";
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
                Console.WriteLine(ex);
            }

            return result;

        }
        public async Task<RequestResult> GetUserDetails(string username, string password)
        {
            RequestResult result = new RequestResult();
            
            try
            {
                GetUserResponse response = new GetUserResponse();

                if (cognitoUserSession != null && cognitoUserSession.IsValid())
                {
                    GetUserRequest userRequest = new GetUserRequest();
                    userRequest.AccessToken = cognitoUserSession.AccessToken;
                    response = await provider.GetUserAsync(userRequest);
                    result.Data = response;
                    result.Status = true;
                }
                else
                {
                    //this.RefreshToken(username);
                    result.Status = false;
                    result.Message = "Not valid session";
                }
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }
        public async Task<RequestResult> UpdateUserDetails(User user)
        {
            RequestResult result = new RequestResult();
            try
            {
                GetUserResponse response = new GetUserResponse();

                if (cognitoUserSession != null && cognitoUserSession.IsValid())
                {
                    List<AttributeType> attributes = new List<AttributeType>();
                    attributes.Add(new AttributeType() { Name = "custom:firstname", Value = user.FirstName });
                    attributes.Add(new AttributeType() { Name = "custom:lastname", Value = user.LastName });

                    UpdateUserAttributesRequest rr = new UpdateUserAttributesRequest()
                    {
                        AccessToken = cognitoUserSession.AccessToken,
                        UserAttributes = attributes
                    };

                    await provider.UpdateUserAttributesAsync(rr);
                    result.Data = response;
                    result.Status = true;
                    result.Message = "User Info updated successfully.";
                }
                else
                {
                    result.Status = false;
                    result.Message = "Invalid Sesson";
                }
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }
        public async Task<RequestResult> UserSignOut(string username, string password)
        {
            RequestResult result = new RequestResult();
            try
            {
                result = await this.AuthnicateUser(username, password);
                if (result.Status)
                {
                    Amazon.Extensions.CognitoAuthentication.CognitoUser user = (Amazon.Extensions.CognitoAuthentication.CognitoUser)result.Data;
                    await user.GlobalSignOutAsync();
                }
            }
            catch (Exception ex)
            {
                result.Status = false;
            }

            return result;
        }
        public async Task<RequestResult> ResetPassword(string username)
        {
            RequestResult result = new RequestResult();
            try
            {
                CognitoUserPool userPool = new CognitoUserPool(this.POOL_ID, this.CLIENTAPP_ID, provider);

                CognitoUser user = new CognitoUser(username, this.CLIENTAPP_ID, userPool, provider);
                await user.ForgotPasswordAsync();
                result.Data = user;
                result.Status = true;
                result.Message = "Password Updated Successfully";
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }
        public async Task<RequestResult> UpdatePassword(string username, string code, string newpassword)
        {
            RequestResult result = new RequestResult();
            try
            {
                CognitoUserPool userPool = new CognitoUserPool(this.POOL_ID, this.CLIENTAPP_ID, provider);

                Amazon.Extensions.CognitoAuthentication.CognitoUser user = new Amazon.Extensions.CognitoAuthentication.CognitoUser(username, this.CLIENTAPP_ID, userPool, provider);

                await user.ConfirmForgotPasswordAsync(code, newpassword);
                result.Data = user;
                result.Status = true;
                result.Message = "Password Updated Successfully";
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }
        public async Task<RequestResult> ChangePassword(string username, string oldpassword, string newpassword)
        {
            RequestResult result = new RequestResult();
            result = await this.AuthnicateUser(username, oldpassword);

            if (result.Status)
            {
                Amazon.Extensions.CognitoAuthentication.CognitoUser user = (Amazon.Extensions.CognitoAuthentication.CognitoUser)result.Data;
                await user.ChangePasswordAsync(oldpassword, newpassword);
                result.Message = "Password Changed Successfully";
            }

            return result;
        }
        public async Task<RequestResult> AuthnicateUser(string username, string password)
        {
            RequestResult result = new RequestResult();
            try
            {
                CognitoUserPool userPool = new CognitoUserPool(this.POOL_ID, this.CLIENTAPP_ID, provider);
                CognitoUser user = new CognitoUser(username, this.CLIENTAPP_ID, userPool, provider);
                
                InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
                {
                    Password = password
                };


                AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);
                if (authResponse.AuthenticationResult != null)
                {
                    cognitoUserSession = new CognitoUserSession(authResponse.AuthenticationResult.IdToken, authResponse.AuthenticationResult.AccessToken, authResponse.AuthenticationResult.RefreshToken, DateTime.Now, DateTime.Now.AddHours(1));
                    //JwtSecurityTokenHandler jt = new JwtSecurityTokenHandler();
                    //if (!jt.CanReadToken(authResponse.AuthenticationResult.AccessToken))
                    //{
                    //}

                    //JwtSecurityToken tokenS = jt.ReadToken(authResponse.AuthenticationResult.AccessToken) as JwtSecurityToken;
                    //result.Id = tokenS.Id;
                    //IEnumerable<Claim> cc = tokenS.Claims;

                    //result.cc = cc;
                    result.Status = true;
                    result.Data = user;
                }
                else
                {
                    result.Status = false;
                }
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }
        public async void RefreshToken(string username)
        {
            CognitoUserPool userPool = new CognitoUserPool(this.POOL_ID, this.CLIENTAPP_ID, provider);
            CognitoUser user = new CognitoUser(username, this.CLIENTAPP_ID, userPool, provider);
            
            InitiateRefreshTokenAuthRequest ra = new InitiateRefreshTokenAuthRequest() { AuthFlowType = AuthFlowType.REFRESH_TOKEN };
            AuthFlowResponse authResponse = await user.StartWithRefreshTokenAuthAsync(ra);

            if (authResponse.AuthenticationResult != null)
            {
                cognitoUserSession = new CognitoUserSession(authResponse.AuthenticationResult.IdToken, authResponse.AuthenticationResult.AccessToken, authResponse.AuthenticationResult.RefreshToken, DateTime.Now, DateTime.Now.AddHours(1));
            }
        }

        public async Task<string> LoginAsync(string username, string password)
        {
            CognitoUserPool userPool = new CognitoUserPool(this.POOL_ID, this.CLIENTAPP_ID, provider);
            Amazon.Extensions.CognitoAuthentication.CognitoUser user = new Amazon.Extensions.CognitoAuthentication.CognitoUser(username, this.CLIENTAPP_ID, userPool, provider);

            InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
            {
                Password = password
            };

            AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);
            if (authResponse.AuthenticationResult != null)
            {
                return authResponse.AuthenticationResult.RefreshToken;
            }

            //var authReq = new AdminInitiateAuthRequest
            //{
            //    UserPoolId = POOL_ID,
            //    ClientId = CLIENTAPP_ID,
            //    AuthFlow = AuthFlowType.ADMIN_NO_SRP_AUTH
            //};
            //authReq.AuthParameters.Add("USERNAME", userName.ToLower());
            //authReq.AuthParameters.Add("PASSWORD", password);

            //AdminInitiateAuthResponse authResp = await provider.AdminInitiateAuthAsync(authReq);

            return authResponse.AuthenticationResult.IdToken;
        }

        public bool Verify(string accessToken)
        {

            JwtSecurityTokenHandler jt = new JwtSecurityTokenHandler();
            JwtSecurityToken tokenS = jt.ReadToken(accessToken) as JwtSecurityToken;

            //string[] parts = accessToken.Split('.');

            //parts[2] = parts[2].PadRight(parts[2].Length + (4 - parts[2].Length % 4) % 4, '=');
            //Console.WriteLine(parts[2]);
            //SecurityToken stt = jt.ReadToken(accessToken);

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
            };


            //SecurityTokenHandler st = new JwtSecurityTokenHandler();
            //st.ValidateToken(tokenS..ToString(), validationParameters, out stt);

            //From the Cognito JWK set
            //{"alg":"RS256","e":"myE","kid":"myKid","kty":"RSA","n":"myN","use":"sig"}]}
            //var n = Base64UrlDecode("q7ocE2u-JSe1P4AF6_Nasae7e7wUoUxJq058CueDFs9R5fvWQTtAN1rMxBCeLQ7Q8Q0u-vqxr83b6N9ZR5zWUU2stgYzrDTANbIn9zMGDZvSR1tMpun5eAArKW5fcxGFj6klQ0bctlUATSGU5y6xmYoe_U9ycLlPxh5mDluR7V6GbunE1IXJHqcyy-s7dxYdGynTbsLemwmyjDaInGGsM3gMdPAJc29PXozm87ZKY52U7XQN0TMB9Ipwsix443zbE_8WX2mvKjU5yvucFdc4WZdoXN9SGs3HGAeL6Asjc0S6DCruuNiKYj4-MkKh_hlTkH7Rj2CeoV7H3GNS0IOqnQ");
            //var e = Base64UrlDecode("AQAB");

            //RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            //provider.ImportParameters(new RSAParameters
            //{
            //    Exponent = new BigInteger(e).ToByteArrayUnsigned(),
            //    Modulus = new BigInteger(n).ToByteArrayUnsigned()
            //});

            //SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            //byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]));

            //RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(provider);
            //rsaDeformatter.SetHashAlgorithm("SHA256");

            //if (!rsaDeformatter.VerifySignature(hash, Base64UrlDecode(parts[2])))
            //    throw new ApplicationException(string.Format("Invalid signature"));

            return true;
        }

        public async Task<RequestResult> DeleteUser()
        {
            RequestResult result = new RequestResult();
            try
            {
                if (cognitoUserSession != null && cognitoUserSession.IsValid())
                {
                    DeleteUserRequest dr = new DeleteUserRequest() { AccessToken = cognitoUserSession.AccessToken };
                    await provider.DeleteUserAsync(dr);
                    result.Status = true;
                    result.Message = "Deleted Successfully";
                }
                else
                {
                    //this.RefreshToken(username);
                    result.Status = false;
                    result.Message = "Not valid session";
                }
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }

        public async Task<RequestResult> DeleteUnConfirmedUser(string username, string password)
        {
            RequestResult result = new RequestResult();
            try
            {
                CognitoUserPool userPool = new CognitoUserPool(this.POOL_ID, this.CLIENTAPP_ID, provider);
                Amazon.Extensions.CognitoAuthentication.CognitoUser user = new Amazon.Extensions.CognitoAuthentication.CognitoUser(username, this.CLIENTAPP_ID, userPool, provider);


                AdminDeleteUserRequest req = new AdminDeleteUserRequest() { Username = username, UserPoolId = POOL_ID };
                AdminDeleteUserResponse response = await provider.AdminDeleteUserAsync(req);


                if (response.HttpStatusCode == HttpStatusCode.OK)
                {
                    result.Status = true;
                    result.Message = "Deleted Successfully";
                }
            }
            catch (Exception ex)
            {
                result.Status = false;
                result.Message = ex.Message;
            }

            return result;
        }

        // from JWT spec
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 1: output += "==="; break; // Three pad chars
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}