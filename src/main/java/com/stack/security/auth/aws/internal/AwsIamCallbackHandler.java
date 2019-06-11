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

import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.KafkaException;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.stack.security.auth.aws.AwsIamAuthenticateCallback;
import com.stack.security.auth.aws.AwsIamLoginModule;

public class AwsIamCallbackHandler implements AuthenticateCallbackHandler {

  private AWSSecurityTokenService service;

  public AwsIamCallbackHandler(AWSSecurityTokenService service) {
    // Allow injection of STS instance for testing
    if (service != null) {
      this.service = service;
    }
  }

  public AwsIamCallbackHandler() {
  }

  private static final String AWS_ACCOUNT_ID = "aws_account_id";
  private List<AppConfigurationEntry> jaasConfigEntries;

  @Override
  public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
    this.jaasConfigEntries = jaasConfigEntries;
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    String arn = null;
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback)
        arn = ((NameCallback) callback).getDefaultName();
      else if (callback instanceof AwsIamAuthenticateCallback) {
        AwsIamAuthenticateCallback awsIamCallback = (AwsIamAuthenticateCallback) callback;
        boolean authenticated = authenticate(arn, awsIamCallback.accessKeyId(), awsIamCallback.secretAccessKey(),
            awsIamCallback.sessionToken());
        awsIamCallback.authenticated(authenticated);
      } else
        throw new UnsupportedCallbackException(callback);
    }
  }

  protected boolean authenticate(String arn, char[] accessKeyId, char[] secretAccessKey, char[] sessionToken) {

    // At a minimum, the ARN, Access Key ID and Secret Access Key MUST be defined!
    if (arn == null || accessKeyId == null || secretAccessKey == null) {
      return false;
    }

    AWSCredentials awsCreds;
    String accessKeyIdString = new String(accessKeyId);
    String secretAccessKeyString = new String(secretAccessKey);
    String sessionTokenString = new String(sessionToken);

    if (!sessionTokenString.isEmpty()) {
      awsCreds = new BasicSessionCredentials(accessKeyIdString, secretAccessKeyString, sessionTokenString);
    } else {
      awsCreds = new BasicAWSCredentials(accessKeyIdString, secretAccessKeyString);
    }
    if (this.service == null) {
      this.service = AWSSecurityTokenServiceClientBuilder.standard()
          .withCredentials(new AWSStaticCredentialsProvider(awsCreds)).build();
    }
    // As an added measure of safety, the server can specify what AWS Account ID it
    // expects to see as a part of the caller's identity.
    String expectedAwsAccountId = JaasContext.configEntryOption(jaasConfigEntries, AWS_ACCOUNT_ID,
        AwsIamLoginModule.class.getName());

    // Check the credentials with AWS STS and GetCallerIdentity.

    GetCallerIdentityRequest request = new GetCallerIdentityRequest();
    GetCallerIdentityResult result = this.service.getCallerIdentity(request);

    // Both the ARN returned by the credentials, and the configured account ID need
    // to match!
    if (result.getArn().equals(arn) && result.getAccount().equals(expectedAwsAccountId)) {
      return true;
    } else {
      return false;
    }
  }

  @Override
  public void close() throws KafkaException {
  }

}
