package com.stack.security.auth.aws.internal;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;

public class AwsIamSaslClient implements SaslClient {

  public static final String AWS_MECHANISM = "AWS";
  public static Charset UTF_8 = Charset.forName("UTF-8");

  protected AWSCredentialsProviderChain provider;
  protected AWSSecurityTokenServiceClientBuilder stsBuilder;

  protected ScheduledExecutorService executor;

  protected CallbackHandler cbh;
  protected String authorizationID; // The Unique UserId from AWS STS
  protected byte[] accessKeyId;
  protected byte[] secretAccessKey;
  protected byte[] sessionToken;
  protected static byte SEP = 0; // Null byte separator for stream

  protected boolean completed;

  /**
   * The default constructor for AwsIamSaslClient. Automatically uses the
   * DefaultAWSCredentialsProviderChain to obtain AWS credentials, and attempts to
   * refresh them every 30 minutes, if applicable.
   */
  public AwsIamSaslClient(CallbackHandler cbh) {
    this(cbh, AWSSecurityTokenServiceClientBuilder.standard(), DefaultAWSCredentialsProviderChain.getInstance(), 30,
        TimeUnit.MINUTES);
  }

  public AwsIamSaslClient(CallbackHandler cbh, AWSSecurityTokenServiceClientBuilder builder) {
    this(cbh, builder, DefaultAWSCredentialsProviderChain.getInstance(), 30, TimeUnit.MINUTES);
  }

  public AwsIamSaslClient(CallbackHandler cbh, AWSSecurityTokenServiceClientBuilder builder,
      AWSCredentialsProviderChain provider) {
    this(cbh, builder, provider, 30, TimeUnit.MINUTES);
  }

  /**
   * Automatically uses the DefaultAWSCredentialsProviderChain to obtain AWS
   * credentials, and attempts to refresh them based on the period and time unit
   * specified.
   */
  public AwsIamSaslClient(CallbackHandler cbh, long period, TimeUnit unit) {
    this(cbh, AWSSecurityTokenServiceClientBuilder.standard(), DefaultAWSCredentialsProviderChain.getInstance(), period,
        unit);
  }

  /**
   * Uses the given AWSCredentialsProviderChain instance, custom period and time
   * unit to obtain credentials for use.
   */
  public AwsIamSaslClient(CallbackHandler cbh, AWSSecurityTokenServiceClientBuilder builder,
      AWSCredentialsProviderChain provider, long period, TimeUnit unit) {
    this.cbh = cbh;
    this.stsBuilder = builder;
    this.provider = provider;

    setCredentials(this.provider.getCredentials());

    // Setup the runner to auto-refresh credentials (if applicable).
    this.executor = Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory());

    Runnable periodicTask = new Runnable() {
      public void run() {
        provider.refresh();
        setCredentials(provider.getCredentials());
      }
    };

    executor.scheduleAtFixedRate(periodicTask, period, period, unit);
  }

  @Override
  public byte[] evaluateChallenge(byte[] challengeData) throws SaslException {
    if (completed) {
      throw new IllegalStateException("AWS authentication already completed");
    }
    completed = true;
    return generateAnswer();
  }

  // Parse the AWSCredentials object into the appropriate byte arrays on the
  // client.
  private void setCredentials(AWSCredentials credentials) {
    // Use the STS service to find the UserId/RoleId of our own credentials.
    // NOTE: The server will independently verify with AWS!
    GetCallerIdentityResult result = AwsIamUtilities.getCallerIdentity(stsBuilder, credentials);
    /**
     * XXX(Kev): Originally, this code stripped the session information off the
     * userId. I've removed it to ensure that the server is properly parsing this
     * information. Clients written in other languages might not strip this
     * information, and it could be useful in the future for things like audit
     * logging and such, so encouraging its removal seems unnecessary at best.
     */
    this.authorizationID = result.getUserId();
    this.accessKeyId = credentials.getAWSAccessKeyId().getBytes(UTF_8);
    this.secretAccessKey = credentials.getAWSSecretKey().getBytes(UTF_8);
    if (credentials instanceof AWSSessionCredentials) {
      AWSSessionCredentials sessionCreds = (AWSSessionCredentials) credentials;
      this.sessionToken = sessionCreds.getSessionToken().getBytes(UTF_8);
    }
    credentials = null;
  }

  protected final byte[] generateAnswer() throws SaslException {

    // There's no way to generate a useful answer if these values are missing!
    if (accessKeyId == null) {
      throw new SaslException("Unable to create client request! 'accessKeyId' must be defined!");
    } else if (secretAccessKey == null) {
      throw new SaslException("Unable to create client request! 'secretAccessKey' must be defined!");
    }

    try {
      byte[] authz = authorizationID.getBytes(UTF_8);

      /*
       * Answer should be the length of the authentication, authorization (if not
       * null), accessKeyId, secretAccessKey, and sessionToken (if not null) plus the
       * number of null separator bytes between them all.
       */
      byte[] answer;
      if (authz != null && sessionToken != null) {
        answer = new byte[authz.length + accessKeyId.length + secretAccessKey.length + sessionToken.length + 4];
      } else {
        answer = new byte[authz.length + accessKeyId.length + secretAccessKey.length + 3];
      }

      int pos = 0;
      System.arraycopy(authz, 0, answer, 0, authz.length);
      pos = authz.length;
      answer[pos++] = SEP;

      System.arraycopy(accessKeyId, 0, answer, pos, accessKeyId.length);
      pos += accessKeyId.length;
      answer[pos++] = SEP;

      System.arraycopy(secretAccessKey, 0, answer, pos, secretAccessKey.length);
      pos += secretAccessKey.length;
      answer[pos++] = SEP;

      if (sessionToken != null) {
        System.arraycopy(sessionToken, 0, answer, pos, sessionToken.length);
        pos += sessionToken.length;
      }

      clearCredentials();
      return answer;
    } catch (Throwable e) {
      throw new SaslException("Error creating authentication answer", e);
    }
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) {
    if (!completed)
      throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(incoming, offset, offset + len);
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) {
    if (!completed)
      throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(outgoing, offset, offset + len);
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if (completed) {
      if (propName.equals(Sasl.QOP)) {
        return "auth";
      } else {
        return null;
      }
    } else {
      throw new IllegalStateException("AWS authentication not completed");
    }
  }

  @Override
  public boolean isComplete() {
    return completed;
  }

  private void clearCredentials() {
    if (accessKeyId != null) {
      for (int i = 0; i < accessKeyId.length; i++) {
        accessKeyId[i] = (byte) 0;
      }
      accessKeyId = null;

    }

    if (secretAccessKey != null) {
      for (int i = 0; i < secretAccessKey.length; i++) {
        secretAccessKey[i] = (byte) 0;
      }
      secretAccessKey = null;
    }

    if (sessionToken != null && sessionToken.length > 0) {
      for (int i = 0; i < sessionToken.length; i++) {
        sessionToken[i] = (byte) 0;
      }
      sessionToken = null;
    }
  }

  @Override
  public void dispose() {
    this.executor.shutdownNow();
    clearCredentials();
    this.provider = null;
  }

  @Override
  public String getMechanismName() {
    return AWS_MECHANISM;
  }

  @Override
  public boolean hasInitialResponse() {
    return true;
  }

  protected void finalize() {
    clearCredentials();
  }

  public static class AwsIamSaslClientFactory implements SaslClientFactory {

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName,
        Map<String, ?> props, CallbackHandler cbh) throws SaslException {
      boolean supported = false;
      for (String mech : mechanisms) {
        if (mech.equals(AWS_MECHANISM)) // Don't bother traversing the getMechanismNames output...
          supported = true;
      }
      if (!supported) {
        throw new SaslException(
            String.format("No supported mechanisms were requested. Supported mechanisms are '%s'.", AWS_MECHANISM));
      }

      return new AwsIamSaslClient(cbh);
    }

    /*
     * Returns the only mechanism, in a string array. This is unlikely to change,
     * but needs to follow this format.
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[] { AWS_MECHANISM };
    }

  }

  class DaemonThreadFactory implements ThreadFactory {
    public Thread newThread(Runnable r) {
      Thread t = new Thread(r);
      t.setDaemon(true);
      return t;
    }
  }
}
