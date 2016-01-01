package org.smssecure.smssecure.protocol;

public class GroupMessagePrefix extends WirePrefix {
  @Override
  public String calculatePrefix(String message) {
    return super.calculateEndSessionPrefix(message);
  }
}
