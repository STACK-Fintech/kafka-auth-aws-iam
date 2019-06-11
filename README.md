# AwsIamLoginModule

This is a custom LoginModule meant to be used with [Kafka](https://kafka.apache.org) and configured
via [JAAS](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html).

## Usage

Copy the `kafka-auth-aws-iam-{VERSION}.jar` file into your Kafka's `libs` directory.
Next, create a JAAS configuration file that looks something like this:

```
KafkaServer {
    com.stack.security.auth.aws.AwsIamLoginModule required
    aws_account_id="1234567890123";
};
```

In the sample configuration, only AWS IAM credentials associated with the given AWS Account ID will
successfully authenticate. This is to prevent a random user from generating AWS IAM
credentials from a totally separate account and connecting to your Kafka brokers with default ACL
permissions.

Next, add the JAAS configuration file as an argument for the `KAFKA_OPTS` environment variable
of your broker(s):
```
export KAFKA_OPTS="-Djava.security.auth.login.config=./config/server-jaas.conf"
bin/kafka-server-start.sh config/server.properties
```

Last, in server.properties, you'll need to add an entry for the callback handler class.
Without this entry, the `SaslServerCallbackhandler` will be used, which will fail!

```
# server.properties

# Should follow the format: listener.name {listener}.aws.sasl.server.callback.handler=com.stack.security.auth.aws.internal.AwsIamCallbackHandler

# So, for SASL_SSL, it should be:
listener.name.sasl_ssl.aws.sasl.server.callback.handler.class=com.stack.security.auth.aws.internal.AwsIamCallbackHandler
```
