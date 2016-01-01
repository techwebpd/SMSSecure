package org.smssecure.smssecure.protocol;

public class LeftGroupPrefix extends WirePrefix {
  @Override
  public String calculatePrefix(String message) {
    return super.calculateEndSessionPrefix(message);
  }
}
