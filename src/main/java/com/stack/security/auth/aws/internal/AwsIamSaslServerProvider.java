package com.stack.security.auth.aws.internal;

import java.security.Provider;
import java.security.Security;

import com.stack.security.auth.aws.internal.AwsIamSaslServer.AwsIamSaslServerFactory;

public class AwsIamSaslServerProvider extends Provider {

  private static final long serialVersionUID = 1L;

  @SuppressWarnings("deprecation")
  protected AwsIamSaslServerProvider() {
    super("SASL/AWS Server Provider", 1.0, "SASL/AWS Server Provider for Kafka");
    put("SaslServerFactory." + AwsIamSaslServer.AWS_MECHANISM, AwsIamSaslServerFactory.class.getName());
  }

  public static void initialize() {
    Security.addProvider(new AwsIamSaslServerProvider());
  }
}
