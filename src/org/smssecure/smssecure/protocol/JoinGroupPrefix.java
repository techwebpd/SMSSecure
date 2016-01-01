package org.smssecure.smssecure.protocol;

public class JoinGroupPrefix extends WirePrefix {
  @Override
  public String calculatePrefix(String message) {
    return super.calculateEndSessionPrefix(message);
  }
}
