# AwsIamLoginModule

This is a custom LoginModule meant to be used with [Kafka](https://kafka.apache.org) and configured
via [JAAS](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html).

## Usage

Add the `AwsIamLoginModule.class` and `AwsIamAuthenticateCallback.class` files to the classpath
of your Kafka broker(s).

Next, create a JAAS configuration file that looks something like this:

```
KafkaClient {
    com.stack.security.auth.aws.AwsIamLoginModule.class required
    aws_account_id=1234567890123
};
```

In the sample configuration, only AWS IAM credentials associated with the given AWS Account ID will
successfully authenticate. This is to prevent a random user from generating AWS IAM
credentials from a totally separate account and connecting to your Kafka brokers with default ACL
permissions.
