package com.stack.security.auth.aws;

import javax.security.auth.callback.Callback;

/*
 * Authentication callback for SASL/AWS authentication. Callback handler must
 * set authenticated flag to true if the client provided password in the callback
 * matches the expected password.
 */
public class AwsIamAuthenticateCallback implements Callback {
  private char[] accessKeyId;
  private char[] secretAccessKey;
  private char[] sessionToken;
  private boolean authenticated;

  /**
   * Creates a callback with the password provided by the client
   * 
   * @param accessKeyId     The AWS Access Key ID provided by the client during
   *                        SASL/AWS authentication
   * @param secretAccessKey The AWS Secret Access Key provided by the client
   *                        during SASL/AWS authentication
   * @param sessionToken    The AWS Session Token provided by the client during
   *                        SASL/AWS authentication
   * @return
   */
  public AwsIamAuthenticateCallback(String accessKeyId, String secretAccessKey, String sessionToken) {
    setAccessKeyId(accessKeyId);
    setSecretAccessKey(secretAccessKey);
    this.secretAccessKey = secretAccessKey.toCharArray();
    this.sessionToken = sessionToken.toCharArray();
  }

  /**
   * Returns the AWS Access Key ID provided by the client during SASL/AWS
   */
  public char[] getAccessKeyId() {
    return accessKeyId;
  }

  /**
   * Returns the AWS Secret Access Key provided by the client during SASL/AWS
   */
  public char[] getSecretAccessKey() {
    return secretAccessKey;
  }

  /**
   * Returns the AWS Session Token provided by the client during SASL/AWS
   */
  public char[] getSessionToken() {
    return sessionToken;
  }

  public void setAccessKeyId(String accessKeyId) {
    this.accessKeyId = accessKeyId.toCharArray();
  }

  public void setSecretAccessKey(String secretAccessKey) {
    this.secretAccessKey = secretAccessKey.toCharArray();
  }

  public void setSessionToken(String sessionToken) {
    this.sessionToken = sessionToken.toCharArray();
  }

  /**
   * Returns true if client password matches expected password, false otherwise.
   * This state is set by the server-side callback handler.
   */
  public boolean authenticated() {
    return this.authenticated;
  }

  /**
   * Sets the authenticated state. This is set by the server-side callback handler
   * by matching the client provided password with the expected password.
   *
   * @param authenticated true indicates successful authentication
   */
  public void authenticated(boolean authenticated) {
    this.authenticated = authenticated;
  }
}
