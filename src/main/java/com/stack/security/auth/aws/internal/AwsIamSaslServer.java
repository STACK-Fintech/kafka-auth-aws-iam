package com.stack.security.auth.aws.internal;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.apache.kafka.common.errors.SaslAuthenticationException;
import com.stack.security.auth.aws.AwsIamAuthenticateCallback;

/**
 * Simple SaslServer implementation for SASL/AWS_IAM. Checks the provided AWS
 * credentials against the AWS STS service and compares the returned identity
 * against the one provided by the user, as well as the allowed AWS Account to
 * authenticate.
 */
public class AwsIamSaslServer implements SaslServer {

  public static final String AWS_IAM_MECHANISM = "AWS_IAM";

  private final CallbackHandler callbackHandler;
  private boolean complete;
  private String authorizationId;

  public AwsIamSaslServer(CallbackHandler callbackHandler) {
    this.callbackHandler = callbackHandler;
  }

  /**
   * @throws SaslAuthenticationException if username/password combination is
   *                                     invalid or if the requested authorization
   *                                     id is not the same as username.
   *                                     <p>
   *                                     <b>Note:</b> This method may throw
   *                                     {@link SaslAuthenticationException} to
   *                                     provide custom error messages to clients.
   *                                     But care should be taken to avoid
   *                                     including any information in the
   *                                     exception message that should not be
   *                                     leaked to unauthenticated clients. It may
   *                                     be safer to throw {@link SaslException}
   *                                     in some cases so that a standard error
   *                                     message is returned to clients.
   *                                     </p>
   */
  @Override
  public byte[] evaluateResponse(byte[] responseBytes) throws SaslAuthenticationException {
    /*
     * Message format (from https://tools.ietf.org/html/rfc4616):
     *
     * message = [authzid] UTF8NUL authcid UTF8NUL passwd authcid = 1*SAFE ; MUST
     * accept up to 255 octets authzid = 1*SAFE ; MUST accept up to 255 octets
     * passwd = 1*SAFE ; MUST accept up to 255 octets UTF8NUL = %x00 ; UTF-8 encoded
     * NUL character
     *
     * SAFE = UTF1 / UTF2 / UTF3 / UTF4 ;; any UTF-8 encoded Unicode character
     * except NUL
     */

    String response = new String(responseBytes, StandardCharsets.UTF_8);
    List<String> tokens = extractTokens(response);
    String authorizationIdFromClient = tokens.get(0);
    String arn = tokens.get(1);
    String accessKeyId = tokens.get(2);
    String secretAccessKey = tokens.get(3);
    String sessionToken;
    try {
      sessionToken = tokens.get(4);
    } catch (Throwable e) {
      // Ignore the exception, just set the token to empty string.
      sessionToken = "";
    }

    if (arn.isEmpty()) {
      throw new SaslAuthenticationException("Authentication failed: arn not specified");
    }
    if (accessKeyId.isEmpty()) {
      throw new SaslAuthenticationException("Authentication failed: accessKeyId not specified");
    }
    if (secretAccessKey.isEmpty()) {
      throw new SaslAuthenticationException("Authentication failed: secretAccessKey not specified");
    }

    NameCallback nameCallback = new NameCallback("arn", arn);
    AwsIamAuthenticateCallback authenticateCallback = new AwsIamAuthenticateCallback(accessKeyId.toCharArray(),
        secretAccessKey.toCharArray(), sessionToken.toCharArray());
    try {
      callbackHandler.handle(new Callback[] { nameCallback, authenticateCallback });
    } catch (Throwable e) {
      throw new SaslAuthenticationException("Authentication failed: credentials for user could not be verified", e);
    }
    if (!authenticateCallback.authenticated())
      throw new SaslAuthenticationException("Authentication failed: Invalid AWS credentials");
    if (!authorizationIdFromClient.isEmpty() && !authorizationIdFromClient.equals(arn))
      throw new SaslAuthenticationException(
          "Authentication failed: Client requested an authorization id that is different from username");

    this.authorizationId = arn;

    complete = true;
    return new byte[0];
  }

  private List<String> extractTokens(String string) {
    List<String> tokens = new ArrayList<>();
    int startIndex = 0;
    for (int i = 0; i < 6; ++i) {
      int endIndex = string.indexOf("\u0000", startIndex);
      if (endIndex == -1) {
        tokens.add(string.substring(startIndex));
        break;
      }
      tokens.add(string.substring(startIndex, endIndex));
      startIndex = endIndex + 1;
    }

    if (tokens.size() < 4 || tokens.size() > 5)
      throw new SaslAuthenticationException(
          "Invalid SASL/AWS_IAM response: expected 4 or 5 tokens, got " + tokens.size());

    return tokens;
  }

  @Override
  public String getAuthorizationID() {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return authorizationId;
  }

  @Override
  public String getMechanismName() {
    return AWS_IAM_MECHANISM;
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return null;
  }

  @Override
  public boolean isComplete() {
    return complete;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(incoming, offset, offset + len);
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(outgoing, offset, offset + len);
  }

  @Override
  public void dispose() {
  }

  public static class AwsIamSaslServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props,
        CallbackHandler cbh) throws SaslException {

      if (!AWS_IAM_MECHANISM.equals(mechanism))
        throw new SaslException(
            String.format("Mechanism \'%s\' is not supported. Only AWS_IAM is supported.", mechanism));

      return new AwsIamSaslServer(cbh);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      if (props == null)
        return new String[] { AWS_IAM_MECHANISM };
      String noPlainText = (String) props.get(Sasl.POLICY_NOPLAINTEXT);
      if ("true".equals(noPlainText))
        return new String[] {};
      else
        return new String[] { AWS_IAM_MECHANISM };
    }
  }
}
