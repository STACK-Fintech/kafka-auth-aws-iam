package com.stack.security.auth.aws.internal;

import java.security.Provider;
import java.security.Security;

import com.stack.security.auth.aws.internal.AwsIamSaslClient.AwsIamSaslClientFactory;

public class AwsIamSaslClientProvider extends Provider {

  private static final long serialVersionUID = 1L;

  @SuppressWarnings("deprecation")
  protected AwsIamSaslClientProvider() {
    super("SASL/AWS Client Provider", 1.0, "SASL/AWS Client Provider for Kafka");
    put("SaslClientFactory." + AwsIamSaslClient.AWS_MECHANISM, AwsIamSaslClientFactory.class.getName());
  }

  public static void initialize() {
    Security.addProvider(new AwsIamSaslClientProvider());
  }
}
