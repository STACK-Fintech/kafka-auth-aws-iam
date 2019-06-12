/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.stack.security.auth.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.stack.security.auth.aws.internal.AwsIamCallbackHandler;
import com.stack.security.auth.aws.internal.AwsIamSaslServer;
import com.stack.security.authenticator.FakeJaasConfig;

import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.security.JaasContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class AwsIamSaslServerTest {
  private static JaasContext jaasContext;

  static final String FAKE_ARN = "arn:aws:iam::000000000000:user/NotARealUser";
  // These credentials have no access to anything, and are purely for testing!
  static final String ARN = "arn:aws:iam::000000000000:user/TestUser";
  static final String AWS_ACCESS_KEY_ID = "<fakeKeyId>";
  static final String AWS_SECRET_ACCESS_KEY = "<fakeSecretKey>";
  static final String AWS_SESSION_TOKEN = "<fakeSessionToken>";
  static final String AWS_ACCOUNT_ID = "000000000000";

  // Static mocks for testing
  static AWSSecurityTokenServiceClientBuilder builder = mock(AWSSecurityTokenServiceClientBuilder.class,
      Mockito.RETURNS_DEEP_STUBS);
  static AWSSecurityTokenService sts;

  @BeforeAll
  public static void setUp() {
    FakeJaasConfig jaasConfig = new FakeJaasConfig();
    HashMap<String, Object> options = new HashMap<String, Object>();
    options.put("aws_account_id", AWS_ACCOUNT_ID);
    jaasConfig.addEntry("jaasContext", AwsIamLoginModule.class.getName(), options);
    jaasContext = new JaasContext("jaasContext", JaasContext.Type.SERVER, jaasConfig, null);
    sts = mock(AWSSecurityTokenService.class);
    when(builder.withCredentials(any(AWSStaticCredentialsProvider.class)).build()).thenReturn(sts);
  }

  @Test
  public void emptyTokens() {
    AwsIamCallbackHandler callbackHandler = new AwsIamCallbackHandler(builder);
    callbackHandler.configure(null, "AWS", jaasContext.configurationEntries());
    AwsIamSaslServer saslServer = new AwsIamSaslServer(callbackHandler);
    Exception e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("", "", "", "", "")));
    assertEquals("Authentication failed: arn not specified", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("", "", "", "p", "")));
    assertEquals("Authentication failed: arn not specified", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("", "u", "", "", "")));
    assertEquals("Authentication failed: accessKeyId not specified", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("a", "", "", "", "")));
    assertEquals("Authentication failed: arn not specified", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("a", "", "p", "", "")));
    assertEquals("Authentication failed: arn not specified", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("a", "u", "", "", "")));
    assertEquals("Authentication failed: accessKeyId not specified", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage("a", "u", "o", "", "")));
    assertEquals("Authentication failed: secretAccessKey not specified", e.getMessage());
    String nul = "\u0000";

    e = assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(String.format("%s%s%s%s%s%s%s%s%s%s%s", ARN, nul, ARN, nul, AWS_ACCESS_KEY_ID,
            nul, AWS_SECRET_ACCESS_KEY, nul, "s", nul, "q").getBytes(StandardCharsets.UTF_8)));
    assertEquals("Invalid SASL/AWS response: expected 4 or 5 tokens, got 6", e.getMessage());

    e = assertThrows(SaslAuthenticationException.class, () -> saslServer.evaluateResponse(
        String.format("%s%s%s%s", ARN, nul, ARN, nul, AWS_ACCESS_KEY_ID, nul).getBytes(StandardCharsets.UTF_8)));
    assertEquals("Invalid SASL/AWS response: expected 4 or 5 tokens, got 3", e.getMessage());
  }

  @Test
  public void authorizationSucceedsWithValidKeys() {
    AwsIamCallbackHandler callbackHandler = new AwsIamCallbackHandler(builder);
    callbackHandler.configure(null, "AWS", jaasContext.configurationEntries());
    AwsIamSaslServer saslServer = new AwsIamSaslServer(callbackHandler);
    GetCallerIdentityResult stsResult = mock(GetCallerIdentityResult.class);
    when(sts.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(stsResult);
    when(stsResult.getAccount()).thenReturn(AWS_ACCOUNT_ID);
    when(stsResult.getArn()).thenReturn(ARN);

    saslServer.evaluateResponse(saslMessage(ARN, ARN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY));
  }

  @Test
  public void authorizationFailsForWrongAuthorizationId() {
    AwsIamCallbackHandler callbackHandler = new AwsIamCallbackHandler(builder);
    callbackHandler.configure(null, "AWS", jaasContext.configurationEntries());
    AwsIamSaslServer saslServer = new AwsIamSaslServer(callbackHandler);
    GetCallerIdentityResult stsResult = mock(GetCallerIdentityResult.class);
    when(sts.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(stsResult);
    when(stsResult.getAccount()).thenReturn(AWS_ACCOUNT_ID);
    when(stsResult.getArn()).thenReturn(ARN);
    assertThrows(SaslAuthenticationException.class,
        () -> saslServer.evaluateResponse(saslMessage(FAKE_ARN, ARN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)));
  }

  @Test
  public void authorizationSucceedsWithValidKeysAndSession() {
    AwsIamCallbackHandler callbackHandler = new AwsIamCallbackHandler(builder);
    callbackHandler.configure(null, "AWS", jaasContext.configurationEntries());
    AwsIamSaslServer saslServer = new AwsIamSaslServer(callbackHandler);
    GetCallerIdentityResult stsResult = mock(GetCallerIdentityResult.class);
    when(sts.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(stsResult);
    when(stsResult.getAccount()).thenReturn(AWS_ACCOUNT_ID);
    when(stsResult.getArn()).thenReturn(ARN);
    byte[] nextChallenge = saslServer
        .evaluateResponse(saslMessage(ARN, ARN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN));
    assertEquals(0, nextChallenge.length);
  }

  @Test()
  public void authorizationFailsForInvalidSession() throws Exception {
    AwsIamCallbackHandler callbackHandler = new AwsIamCallbackHandler(builder);
    callbackHandler.configure(null, "AWS", jaasContext.configurationEntries());
    AwsIamSaslServer saslServer = new AwsIamSaslServer(callbackHandler);
    when(sts.getCallerIdentity(any(GetCallerIdentityRequest.class)))
        .thenThrow(new SaslAuthenticationException("Invalid session token"));

    assertThrows(SaslAuthenticationException.class, () -> saslServer
        .evaluateResponse(saslMessage(ARN, ARN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "totallyBogusToken")));
  }

  private byte[] saslMessage(String authorizationId, String arn, String accessKeyId, String secretAccessKey) {
    String nul = "\u0000";
    String message = String.format("%s%s%s%s%s%s%s", authorizationId, nul, arn, nul, accessKeyId, nul, secretAccessKey);
    return message.getBytes(StandardCharsets.UTF_8);
  }

  private byte[] saslMessage(String authorizationId, String arn, String accessKeyId, String secretAccessKey,
      String sessionToken) {
    String nul = "\u0000";
    String message = String.format("%s%s%s%s%s%s%s%s%s", authorizationId, nul, arn, nul, accessKeyId, nul,
        secretAccessKey, nul, sessionToken);
    return message.getBytes(StandardCharsets.UTF_8);
  }
}
