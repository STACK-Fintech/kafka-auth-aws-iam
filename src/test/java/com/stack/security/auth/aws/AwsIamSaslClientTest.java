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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.stack.security.auth.aws.internal.AwsIamServerCallbackHandler;
import com.stack.security.auth.aws.internal.AwsIamSaslClient;
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
public class AwsIamSaslClientTest {
  private static JaasContext clientContext;
  private static JaasContext serverContext;

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
  static DefaultAWSCredentialsProviderChain chain = mock(DefaultAWSCredentialsProviderChain.class,
      Mockito.RETURNS_DEEP_STUBS);
  static CallbackHandler handler = mock(CallbackHandler.class, Mockito.RETURNS_DEEP_STUBS);
  static AWSSecurityTokenService sts;

  @BeforeAll
  public static void setUp() {
    FakeJaasConfig jaasConfig = new FakeJaasConfig();
    HashMap<String, Object> options = new HashMap<String, Object>();
    options.put("aws_account_id", AWS_ACCOUNT_ID);
    jaasConfig.addEntry("serverContext", AwsIamLoginModule.class.getName(), options);
    jaasConfig.addEntry("clientContext", AwsIamLoginModule.class.getName(), new HashMap<String, Object>());
    clientContext = new JaasContext("clientContext", JaasContext.Type.CLIENT, jaasConfig, null);
    serverContext = new JaasContext("serverContext", JaasContext.Type.SERVER, jaasConfig, null);
    sts = mock(AWSSecurityTokenService.class);
    when(builder.withCredentials(any(AWSStaticCredentialsProvider.class)).build()).thenReturn(sts);
  }

  @Test
  public void handlesBasicCredentials() throws SaslException {
    AWSCredentials fakeCreds = new BasicAWSCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY);
    assertDoesNotThrow(() -> {
      checkAuthentication(fakeCreds);
    });
  }

  @Test
  public void handlesSessionCredentials() throws SaslException {
    AWSCredentials fakeCreds = new BasicSessionCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN);
    assertDoesNotThrow(() -> {
      checkAuthentication(fakeCreds);
    });
  }

  public void checkAuthentication(AWSCredentials credentials) throws SaslException {
    when(chain.getCredentials()).thenReturn(credentials);
    AwsIamServerCallbackHandler callbackHandler = new AwsIamServerCallbackHandler(builder);
    callbackHandler.configure(null, "AWS", serverContext.configurationEntries());
    AwsIamSaslServer saslServer = new AwsIamSaslServer(callbackHandler);
    GetCallerIdentityResult stsResult = mock(GetCallerIdentityResult.class);
    when(sts.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(stsResult);
    when(stsResult.getAccount()).thenReturn(AWS_ACCOUNT_ID);
    when(stsResult.getArn()).thenReturn(ARN);

    AwsIamSaslClient saslClient = new AwsIamSaslClient(handler, builder, chain);
    byte[] result = saslClient.evaluateChallenge(new byte[0]);

    // Use AwsIamSaslServer to evaluate messages generated by the client!
    byte[] authResult = saslServer.evaluateResponse(result);
    assertEquals(authResult.length, 0);
  }

}
