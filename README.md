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

Finally, add the JAAS configuration file as an argument for the `KAFKA_OPTS` environment variable
of your broker(s):
```
export KAFKA_OPTS="-Djava.security.auth.login.config=./config/server-jaas.conf"
bin/kafka-server-start.sh config/server.properties
```
