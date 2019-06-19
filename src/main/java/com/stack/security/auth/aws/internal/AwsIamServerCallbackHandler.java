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

package com.stack.security.auth.aws.internal;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.stack.security.auth.aws.AwsIamAuthenticateCallback;
import com.stack.security.auth.aws.AwsIamLoginModule;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;

public class AwsIamServerCallbackHandler implements AuthenticateCallbackHandler {

  private AWSSecurityTokenServiceClientBuilder builder;

  public AwsIamServerCallbackHandler(AWSSecurityTokenServiceClientBuilder builder) {
    // Allow injection of STS instance for testing
    if (builder != null) {
      this.builder = builder;
    }
  }

  public AwsIamServerCallbackHandler() {
    this.builder = AWSSecurityTokenServiceClientBuilder.standard();
  }

  private static final String AWS_ACCOUNT_ID = "aws_account_id";
  private List<AppConfigurationEntry> jaasConfigEntries;

  @Override
  public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
    this.jaasConfigEntries = jaasConfigEntries;
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    String authorizationId = null;
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback)
        authorizationId = ((NameCallback) callback).getDefaultName();
      else if (callback instanceof AwsIamAuthenticateCallback) {
        AwsIamAuthenticateCallback awsIamCallback = (AwsIamAuthenticateCallback) callback;
        boolean authenticated = authenticate(authorizationId, awsIamCallback.getAccessKeyId(),
            awsIamCallback.getSecretAccessKey(), awsIamCallback.getSessionToken());
        awsIamCallback.authenticated(authenticated);
      } else
        throw new UnsupportedCallbackException(callback);
    }
  }

  protected boolean authenticate(String authorizationId, char[] accessKeyId, char[] secretAccessKey,
      char[] sessionToken) {

    // At a minimum, the authorizationId, Access Key ID and Secret Access Key MUST
    // be defined!
    if (authorizationId == null || accessKeyId == null || secretAccessKey == null) {
      return false;
    }

    String accessKeyIdString = new String(accessKeyId);
    String secretAccessKeyString = new String(secretAccessKey);
    String sessionTokenString = sessionToken == null ? "" : new String(sessionToken);

    if (authorizationId.isEmpty() || accessKeyIdString.isEmpty() || secretAccessKeyString.isEmpty()) {
      return false;
    }
    // As an added measure of safety, the server can specify what AWS Account ID it
    // expects to see as a part of the caller's identity.
    String expectedAwsAccountId = JaasContext.configEntryOption(jaasConfigEntries, AWS_ACCOUNT_ID,
        AwsIamLoginModule.class.getName());

    // Check the credentials with AWS STS and GetCallerIdentity.
    GetCallerIdentityResult result = AwsIamUtilities.getCallerIdentity(builder, accessKeyIdString,
        secretAccessKeyString, sessionTokenString);

    // Both the ARN returned by the credentials, and the configured account ID need
    // to match!
    if (result.getUserId().equals(authorizationId) && result.getAccount().equals(expectedAwsAccountId)) {
      return true;
    } else {
      return false;
    }
  }

  @Override
  public void close() throws KafkaException {
  }

}
