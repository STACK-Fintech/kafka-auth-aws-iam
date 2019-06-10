package com.stack.security.auth.aws;

import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

import com.stack.security.auth.aws.internal.AwsIamSaslServerProvider;

public class AwsIamLoginModule implements LoginModule {

  private static final String ARN = "arn";
  private static final String AWS_ACCESS_KEY_ID = "accessKeyId";
  private static final String AWS_SECRET_ACCESS_KEY = "secretAccessKey";
  private static final String AWS_SESSION_TOKEN = "sessionToken";

  static {
    AwsIamSaslServerProvider.initialize();
  }

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
      Map<String, ?> options) {

    Set<Object> publicCredentials = subject.getPublicCredentials();
    Set<Object> privateCredentials = subject.getPrivateCredentials();
    String arn = (String) options.get(ARN);
    if (arn != null) {
      publicCredentials.add(arn);
    }
    String accessKeyId = (String) options.get(AWS_ACCESS_KEY_ID);
    if (accessKeyId != null) {
      privateCredentials.add(accessKeyId);
    }
    String secretKey = (String) options.get(AWS_SECRET_ACCESS_KEY);
    if (secretKey != null) {
      privateCredentials.add(secretKey);
    }
    String sessionToken = (String) options.get(AWS_SESSION_TOKEN);
    if (sessionToken != null) {
      privateCredentials.add(sessionToken);
    }
  }

  @Override
  public boolean login() {
    return true;
  }

  @Override
  public boolean logout() {
    return true;
  }

  @Override
  public boolean commit() {
    return true;
  }

  @Override
  public boolean abort() {
    return false;
  }
}
