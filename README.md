# AwsIamLoginModule

This is a custom LoginModule meant to be used with [Kafka](https://kafka.apache.org) and configured
via [JAAS](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html).

## Special Thanks
A shoutout to @CookPete for creating [auto-changelog](https://github.com/CookPete/auto-changelog),
which is used to build the CHANGELOG for this plugin!

## Server Setup

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

Last, in server.properties, you'll need to add:
- an entry for the callback handler class
- the selected SASL mechanism
- a list of enabled SASL mechanisms

```
# server.properties

sasl.mechanism=AWS
# You can add other mechanisms as necessary
sasl.enabled.mechanisms=AWS
# If you want Kafka brokers to communicate securely
sasl.mechanism.inter.broker.protocol=AWS 

# Should follow the format: listener.name.{listener}.aws.sasl.server.callback.handler=com.stack.security.auth.aws.internal.AwsIamCallbackHandler
listener.name.sasl_ssl.aws.sasl.server.callback.handler.class=com.stack.security.auth.aws.internal.AwsIamCallbackHandler
```

## Client Setup

You can use the AwsIamLoginModule for authentication between Kafka Brokers. To do this,
add an entry to your JAAS configuration for `KafkaClient`:

```
KafkaClient {
    com.stack.security.auth.aws.AwsIamLoginModule required;
};
```

The `AwsIamSaslClient` leverages the [DefaultAWSCredentialsProviderChain](https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/auth/DefaultAWSCredentialsProviderChain.html) to automatically find credentials available for use in
the environment of your Kafka broker.

Unlike the `AwsIamSaslServer`, the `AwsIamSaslClient` does not use a custom callback so no
additional wireup is needed in server.properties.

This client can also be used with JAAS-compatible Consumers and Producers, though this hasn't been
tested.


## Build, Test, etc...
This project uses [Maven](https://maven.apache.org/).
```
# Install dependencies
mvn install
# Build
mvn compile
# Test
mvn test
# Package the JAR for use
mvn package
```

-----
Built with :heart: by

<a href="https://www.getstack.ca/"><img src="https://s3.ca-central-1.amazonaws.com/images.getstack.ca/static/logo--stack--black.png"  width="130px" /></a>
