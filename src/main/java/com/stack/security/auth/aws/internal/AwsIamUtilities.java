package com.stack.security.auth.aws.internal;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;

public final class AwsIamUtilities {

  public static GetCallerIdentityResult getCallerIdentity(String accessKeyId, String secretAccessKey,
      String sessionToken) {
    return getCallerIdentity(AWSSecurityTokenServiceClientBuilder.standard(), accessKeyId, secretAccessKey,
        sessionToken);
  }

  public static GetCallerIdentityResult getCallerIdentity(AWSSecurityTokenServiceClientBuilder builder,
      AWSCredentials credentials) {
    if (credentials instanceof AWSSessionCredentials) {
      AWSSessionCredentials sessionCreds = (AWSSessionCredentials) credentials;
      return getCallerIdentity(builder, sessionCreds.getAWSAccessKeyId(), sessionCreds.getAWSSecretKey(),
          sessionCreds.getSessionToken());
    }
    return getCallerIdentity(builder, credentials.getAWSAccessKeyId(), credentials.getAWSSecretKey(), "");
  }

  /**
   * 
   * @param builder         An instance of the
   *                        AWSSecurityTokenServiceClientBuilder. Provided mainly
   *                        to allow testing via mocks, but can be overridden as
   *                        necessary.
   * @param accessKeyId     The AWS_ACCESS_KEY_ID string.
   * @param secretAccessKey the AWS_SECRET_ACCESS_KEY string.
   * @param sessionToken    the AWS_SESSION_TOKEN string.
   * @return The GetCallerIdentityResult object that represents the identity of
   *         the credentials.
   */
  public static GetCallerIdentityResult getCallerIdentity(AWSSecurityTokenServiceClientBuilder builder,
      String accessKeyId, String secretAccessKey, String sessionToken) {
    if (accessKeyId == null || secretAccessKey == null) {
      throw new IllegalArgumentException("'accessKeyId' and 'secretAccessKey' cannot be null!");
    }

    if (accessKeyId.isBlank() || secretAccessKey.isBlank()) {
      throw new IllegalArgumentException("'accessKeyId' and 'secretAccessKey' cannot be empty/whitespace!");
    }

    AWSCredentials awsCreds;
    if (sessionToken == null || !sessionToken.isEmpty()) {
      awsCreds = new BasicSessionCredentials(accessKeyId, secretAccessKey, sessionToken);
    } else {
      awsCreds = new BasicAWSCredentials(accessKeyId, secretAccessKey);
    }
    AWSSecurityTokenService service = builder.withCredentials(new AWSStaticCredentialsProvider(awsCreds)).build();
    GetCallerIdentityResult result = service.getCallerIdentity(new GetCallerIdentityRequest());
    return result;
  }

  public static String getUniqueIdentity(AWSSecurityTokenServiceClientBuilder builder, String accessKeyId,
      String secretAccessKey, String sessionToken) {
    GetCallerIdentityResult result = getCallerIdentity(builder, accessKeyId, secretAccessKey, sessionToken);
    return getUniqueIdentity(result);
  }

  public static String getUniqueIdentity(String accessKeyId, String secretAccessKey, String sessionToken) {
    GetCallerIdentityResult result = getCallerIdentity(accessKeyId, secretAccessKey, sessionToken);
    return getUniqueIdentity(result);
  }

  public static String getUniqueIdentity(GetCallerIdentityResult result) {
    String userId = result.getUserId();
    // User IDs for sessions follow the format of {uniqueId}:{sessionName},
    // so we should strip it from the identity string.
    int index = userId.indexOf(":");
    return index == -1 ? userId : userId.substring(0, index);
  }
}
