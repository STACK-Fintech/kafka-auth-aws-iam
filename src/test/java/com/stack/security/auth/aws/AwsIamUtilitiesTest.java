package com.stack.security.auth.aws;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.stack.security.auth.aws.internal.AwsIamUtilities;

@ExtendWith(MockitoExtension.class)
public class AwsIamUtilitiesTest {

  static AWSSecurityTokenServiceClientBuilder builder;
  static AWSSecurityTokenService sts;
  static GetCallerIdentityResult result;
  static final String AWS_ACCESS_KEY_ID = "<fakeKeyId>";
  static final String AWS_SECRET_ACCESS_KEY = "<fakeSecretKey>";
  static final String AWS_SESSION_TOKEN = "<fakeSessionToken>";

  @BeforeAll
  public static void setUp() {
    builder = mock(AWSSecurityTokenServiceClientBuilder.class, Mockito.RETURNS_DEEP_STUBS);
    sts = mock(AWSSecurityTokenService.class, Mockito.RETURNS_DEEP_STUBS);
    when(builder.withCredentials(any(AWSStaticCredentialsProvider.class)).build()).thenReturn(sts);
    result = mock(GetCallerIdentityResult.class);
    when(sts.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(result);
  }

  @Test
  public void uniqueIdentityReturnsWithoutSessionToken() {
    when(result.getUserId()).thenReturn("TEST");
    assertEquals("TEST", AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, ""));
    assertEquals("TEST", AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, null));
  }

  @Test
  public void uniqueIdentityReturnsWithSessionToken() {
    when(result.getUserId()).thenReturn("TEST");
    assertEquals("TEST",
        AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN));
  }

  @Test
  public void uniqueIdentityRemovesSessionFromUserId() {
    when(result.getUserId()).thenReturn("TEST:i-0123456789012");
    assertEquals("TEST", AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, ""));
    assertEquals("TEST",
        AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN));
  }

  @Test
  public void uniqueIdentityThrowsOnMissingKeyPair() {
    assertThrows(IllegalArgumentException.class, () -> {
      AwsIamUtilities.getUniqueIdentity(builder, "", AWS_SECRET_ACCESS_KEY, "");
    });
    assertThrows(IllegalArgumentException.class, () -> {
      AwsIamUtilities.getUniqueIdentity(builder, null, AWS_SECRET_ACCESS_KEY, "");
    });
    assertThrows(IllegalArgumentException.class, () -> {
      AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, "", "");
    });
    assertThrows(IllegalArgumentException.class, () -> {
      AwsIamUtilities.getUniqueIdentity(builder, AWS_ACCESS_KEY_ID, null, "");
    });
  }
}
