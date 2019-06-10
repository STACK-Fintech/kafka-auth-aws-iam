/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.stack.security.authenticator;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import com.stack.security.auth.aws.AwsIamLoginModule;
import org.apache.kafka.common.config.types.Password;

public class FakeJaasConfig extends Configuration {

  private Map<String, AppConfigurationEntry[]> entryMap = new HashMap<>();

  static final String LOGIN_CONTEXT_CLIENT = "KafkaClient";
  static final String LOGIN_CONTEXT_SERVER = "KafkaServer";

  static final String ARN = "arn";
  static final String ARN_VALUE = "arn:aws:iam::315923181744:user/TestUser";

  // These credentials have no access to anything, and are purely for testing!
  static final String AWS_ACCESS_KEY_ID = "accessKeyId";
  static final String AWS_ACCESS_KEY_ID_VALUE = "AKIAUTDT5GCYBPMQJFWO";

  static final String AWS_SECRET_ACCESS_KEY = "secretAccessKey";
  static final String AWS_SECRET_ACCESS_KEY_VALUE = "i8lBwcPgkJ8j1+k/2yNHBZKDSYk+HgNC3KzOnC/4";

  static final String AWS_ACCOUNT_ID = "aws_account_id";
  static final String AWS_ACCOUNT_ID_VALUE = "315923181744";

  public static FakeJaasConfig createConfiguration(String clientMechanism, List<String> serverMechanisms) {
    FakeJaasConfig config = new FakeJaasConfig();
    config.createOrUpdateEntry(LOGIN_CONTEXT_CLIENT, loginModule(clientMechanism), defaultClientOptions());
    for (String mechanism : serverMechanisms) {
      config.addEntry(LOGIN_CONTEXT_SERVER, loginModule(mechanism), defaultServerOptions(mechanism));
    }
    Configuration.setConfiguration(config);
    return config;
  }

  @Override
  public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
    return this.entryMap.get(name);
  }

  public static Password jaasConfigProperty(String mechanism, String username, String password) {
    return new Password(loginModule(mechanism) + " required username=" + username + " password=" + password + ";");
  }

  public static Password jaasConfigProperty(String mechanism, Map<String, Object> options) {
    StringBuilder builder = new StringBuilder();
    builder.append(loginModule(mechanism));
    builder.append(" required");
    for (Map.Entry<String, Object> option : options.entrySet()) {
      builder.append(' ');
      builder.append(option.getKey());
      builder.append('=');
      builder.append(option.getValue());
    }
    builder.append(';');
    return new Password(builder.toString());
  }

  public void createOrUpdateEntry(String name, String loginModule, Map<String, Object> options) {
    AppConfigurationEntry entry = new AppConfigurationEntry(loginModule, LoginModuleControlFlag.REQUIRED, options);
    entryMap.put(name, new AppConfigurationEntry[] { entry });
  }

  public void addEntry(String name, String loginModule, Map<String, Object> options) {
    AppConfigurationEntry entry = new AppConfigurationEntry(loginModule, LoginModuleControlFlag.REQUIRED, options);
    AppConfigurationEntry[] existing = entryMap.get(name);
    AppConfigurationEntry[] newEntries = existing == null ? new AppConfigurationEntry[1]
        : Arrays.copyOf(existing, existing.length + 1);
    newEntries[newEntries.length - 1] = entry;
    entryMap.put(name, newEntries);
  }

  private static String loginModule(String mechanism) {
    String loginModule;
    switch (mechanism) {
    case "AWS":
      loginModule = AwsIamLoginModule.class.getName();
      break;
    default:
      throw new IllegalArgumentException("Unsupported mechanism " + mechanism);
    }
    return loginModule;
  }

  public static Map<String, Object> defaultClientOptions() {
    Map<String, Object> options = new HashMap<>();
    options.put(ARN, ARN_VALUE);
    options.put(AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY_ID_VALUE);
    options.put(AWS_SECRET_ACCESS_KEY, AWS_SECRET_ACCESS_KEY_VALUE);
    return options;
  }

  public static Map<String, Object> defaultServerOptions(String mechanism) {
    Map<String, Object> options = new HashMap<>();
    switch (mechanism) {
    case "AWS":
      options.put(AWS_ACCOUNT_ID, AWS_ACCOUNT_ID_VALUE);
      break;
    default:
      throw new IllegalArgumentException("Unsupported mechanism " + mechanism);
    }
    return options;
  }

}
