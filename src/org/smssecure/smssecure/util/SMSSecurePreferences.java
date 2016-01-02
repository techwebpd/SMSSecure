package org.smssecure.smssecure.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.support.annotation.ArrayRes;
import android.support.annotation.NonNull;
import android.util.Log;

import org.smssecure.smssecure.R;
import org.smssecure.smssecure.preferences.NotificationPrivacyPreference;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SMSSecurePreferences {

  private static final String TAG = SMSSecurePreferences.class.getSimpleName();

  public  static final String CHANGE_PASSPHRASE_PREF           = "pref_change_passphrase";
  public  static final String DISABLE_PASSPHRASE_PREF          = "pref_disable_passphrase";
  public  static final String THEME_PREF                       = "pref_theme";
  public  static final String LANGUAGE_PREF                    = "pref_language";
  private static final String MMSC_CUSTOM_HOST_PREF            = "pref_apn_mmsc_custom_host";
  public  static final String MMSC_HOST_PREF                   = "pref_apn_mmsc_host";
  private static final String MMSC_CUSTOM_PROXY_PREF           = "pref_apn_mms_custom_proxy";
  public  static final String MMSC_PROXY_HOST_PREF             = "pref_apn_mms_proxy";
  private static final String MMSC_CUSTOM_PROXY_PORT_PREF      = "pref_apn_mms_custom_proxy_port";
  public  static final String MMSC_PROXY_PORT_PREF             = "pref_apn_mms_proxy_port";
  private static final String MMSC_CUSTOM_USERNAME_PREF        = "pref_apn_mmsc_custom_username";
  public  static final String MMSC_USERNAME_PREF               = "pref_apn_mmsc_username";
  private static final String MMSC_CUSTOM_PASSWORD_PREF        = "pref_apn_mmsc_custom_password";
  public  static final String MMSC_PASSWORD_PREF               = "pref_apn_mmsc_password";
  public  static final String THREAD_TRIM_LENGTH               = "pref_trim_length";
  public  static final String THREAD_TRIM_NOW                  = "pref_trim_now";
  public  static final String ENABLE_MANUAL_MMS_PREF           = "pref_enable_manual_mms";

  private static final String LAST_VERSION_CODE_PREF           = "last_version_code";
  private static final String IS_FIRST_RUN                     = "is_first_run";
  public  static final String RINGTONE_PREF                    = "pref_key_ringtone";
  private static final String VIBRATE_PREF                     = "pref_key_vibrate";
  private static final String NOTIFICATION_PREF                = "pref_key_enable_notifications";
  public  static final String LED_COLOR_PREF                   = "pref_led_color";
  public  static final String LED_BLINK_PREF                   = "pref_led_blink";
  private static final String LED_BLINK_PREF_CUSTOM            = "pref_led_blink_custom";
  public  static final String ALL_MMS_PREF                     = "pref_all_mms";
  public  static final String ALL_SMS_PREF                     = "pref_all_sms";
  public  static final String PASSPHRASE_TIMEOUT_INTERVAL_PREF = "pref_timeout_interval";
  private static final String PASSPHRASE_TIMEOUT_PREF          = "pref_timeout_passphrase";
  private static final String AUTO_KEY_EXCHANGE_PREF           = "pref_auto_complete_key_exchange";
  public  static final String SCREEN_SECURITY_PREF             = "pref_screen_security";
  public  static final String ENTER_KEY_TYPE                   = "pref_enter_key_type";
  private static final String SMS_DELIVERY_REPORT_PREF         = "pref_delivery_report_sms";
  private static final String SMS_DELIVERY_REPORT_TOAST_PREF   = "pref_delivery_report_toast_sms";
  public  static final String MMS_USER_AGENT                   = "pref_mms_user_agent";
  private static final String MMS_CUSTOM_USER_AGENT            = "pref_custom_mms_user_agent";
  private static final String THREAD_TRIM_ENABLED              = "pref_trim_threads";
  private static final String LOCAL_NUMBER_PREF                = "pref_local_number";
  private static final String VERIFYING_STATE_PREF             = "pref_verifying";
  private static final String PROMPTED_DEFAULT_SMS_PREF        = "pref_prompted_default_sms";
  private static final String IN_THREAD_NOTIFICATION_PREF      = "pref_key_inthread_notifications";
  public  static final String REPEAT_ALERTS_PREF               = "pref_repeat_alerts";
  private static final String DISABLE_EMOJI_DRAWER             = "pref_disable_emoji_drawer";
  private static final String SHOW_SENT_TIME                   = "pref_show_sent_time";

  private static final String WIFI_SMS_PREF                    = "pref_wifi_sms";

  private static final String RATING_LATER_PREF                = "pref_rating_later";
  private static final String RATING_ENABLED_PREF              = "pref_rating_enabled";
  public  static final String NOTIFICATION_PRIVACY_PREF        = "pref_notification_privacy";

  private static final String MEDIA_DOWNLOAD_PREF              = "pref_media_download";
  private static final String MEDIA_DOWNLOAD_ROAMING_PREF      = "pref_media_download_roaming";

  public static NotificationPrivacyPreference getNotificationPrivacy(Context context) {
    return new NotificationPrivacyPreference(getStringPreference(context, NOTIFICATION_PRIVACY_PREF, "all"));
  }

  public static long getRatingLaterTimestamp(Context context) {
    return getLongPreference(context, RATING_LATER_PREF, 0);
  }

  public static void setRatingLaterTimestamp(Context context, long timestamp) {
    setLongPreference(context, RATING_LATER_PREF, timestamp);
  }

  public static boolean isRatingEnabled(Context context) {
    return getBooleanPreference(context, RATING_ENABLED_PREF, true);
  }

  public static void setRatingEnabled(Context context, boolean enabled) {
    setBooleanPreference(context, RATING_ENABLED_PREF, enabled);
  }

  public static boolean isWifiSmsEnabled(Context context) {
    return getBooleanPreference(context, WIFI_SMS_PREF, false);
  }

  public static int getRepeatAlertsCount(Context context) {
    try {
      return Integer.parseInt(getStringPreference(context, REPEAT_ALERTS_PREF, "0"));
    } catch (NumberFormatException e) {
      Log.w(TAG, e);
      return 0;
    }
  }

  public static void setRepeatAlertsCount(Context context, int count) {
    setStringPreference(context, REPEAT_ALERTS_PREF, String.valueOf(count));
  }

  public static boolean isInThreadNotifications(Context context) {
    return getBooleanPreference(context, IN_THREAD_NOTIFICATION_PREF, true);
  }

  public static String getLocalNumber(Context context) {
    return getStringPreference(context, LOCAL_NUMBER_PREF, "No Stored Number");
  }

  public static void setLocalNumber(Context context, String localNumber) {
    setStringPreference(context, LOCAL_NUMBER_PREF, localNumber);
  }

  public static String getEnterKeyType(Context context){
    return getStringPreference(context, ENTER_KEY_TYPE, "enter");
  }

  public static boolean isPasswordDisabled(Context context) {
    return getBooleanPreference(context, DISABLE_PASSPHRASE_PREF, false);
  }

  public static void setPasswordDisabled(Context context, boolean disabled) {
    setBooleanPreference(context, DISABLE_PASSPHRASE_PREF, disabled);
  }

  public static boolean getUseCustomMmsc(Context context) {
    boolean legacy = SMSSecurePreferences.isLegacyUseLocalApnsEnabled(context);
    return getBooleanPreference(context, MMSC_CUSTOM_HOST_PREF, legacy);
  }

  public static void setUseCustomMmsc(Context context, boolean value) {
    setBooleanPreference(context, MMSC_CUSTOM_HOST_PREF, value);
  }

  public static String getMmscUrl(Context context) {
    return getStringPreference(context, MMSC_HOST_PREF, "");
  }

  public static void setMmscUrl(Context context, String mmsc) {
    setStringPreference(context, MMSC_HOST_PREF, mmsc);
  }

  public static boolean getUseCustomMmscProxy(Context context) {
    boolean legacy = SMSSecurePreferences.isLegacyUseLocalApnsEnabled(context);
    return getBooleanPreference(context, MMSC_CUSTOM_PROXY_PREF, legacy);
  }

  public static void setUseCustomMmscProxy(Context context, boolean value) {
    setBooleanPreference(context, MMSC_CUSTOM_PROXY_PREF, value);
  }

  public static String getMmscProxy(Context context) {
    return getStringPreference(context, MMSC_PROXY_HOST_PREF, "");
  }

  public static void setMmscProxy(Context context, String value) {
    setStringPreference(context, MMSC_PROXY_HOST_PREF, value);
  }

  public static boolean getUseCustomMmscProxyPort(Context context) {
    boolean legacy = SMSSecurePreferences.isLegacyUseLocalApnsEnabled(context);
    return getBooleanPreference(context, MMSC_CUSTOM_PROXY_PORT_PREF, legacy);
  }

  public static void setUseCustomMmscProxyPort(Context context, boolean value) {
    setBooleanPreference(context, MMSC_CUSTOM_PROXY_PORT_PREF, value);
  }

  public static String getMmscProxyPort(Context context) {
    return getStringPreference(context, MMSC_PROXY_PORT_PREF, "");
  }

  public static void setMmscProxyPort(Context context, String value) {
    setStringPreference(context, MMSC_PROXY_PORT_PREF, value);
  }

  public static boolean getUseCustomMmscUsername(Context context) {
    boolean legacy = SMSSecurePreferences.isLegacyUseLocalApnsEnabled(context);
    return getBooleanPreference(context, MMSC_CUSTOM_USERNAME_PREF, legacy);
  }

  public static void setUseCustomMmscUsername(Context context, boolean value) {
    setBooleanPreference(context, MMSC_CUSTOM_USERNAME_PREF, value);
  }

  public static String getMmscUsername(Context context) {
    return getStringPreference(context, MMSC_USERNAME_PREF, "");
  }

  public static void setMmscUsername(Context context, String value) {
    setStringPreference(context, MMSC_USERNAME_PREF, value);
  }

  public static boolean getUseCustomMmscPassword(Context context) {
    boolean legacy = SMSSecurePreferences.isLegacyUseLocalApnsEnabled(context);
    return getBooleanPreference(context, MMSC_CUSTOM_PASSWORD_PREF, legacy);
  }

  public static void setUseCustomMmscPassword(Context context, boolean value) {
    setBooleanPreference(context, MMSC_CUSTOM_PASSWORD_PREF, value);
  }

  public static String getMmscPassword(Context context) {
    return getStringPreference(context, MMSC_PASSWORD_PREF, "");
  }

  public static void setMmscPassword(Context context, String value) {
    setStringPreference(context, MMSC_PASSWORD_PREF, value);
  }

  public static String getMmsUserAgent(Context context, String defaultUserAgent) {
    boolean useCustom = getBooleanPreference(context, MMS_CUSTOM_USER_AGENT, false);

    if (useCustom) return getStringPreference(context, MMS_USER_AGENT, defaultUserAgent);
    else           return defaultUserAgent;
  }

  public static boolean isAutoRespondKeyExchangeEnabled(Context context) {
    return getBooleanPreference(context, AUTO_KEY_EXCHANGE_PREF, true);
  }

  public static boolean isScreenSecurityEnabled(Context context) {
    return getBooleanPreference(context, SCREEN_SECURITY_PREF, true);
  }

  public static boolean isLegacyUseLocalApnsEnabled(Context context) {
    return getBooleanPreference(context, ENABLE_MANUAL_MMS_PREF, false);
  }

  public static int getLastVersionCode(Context context) {
    return getIntegerPreference(context, LAST_VERSION_CODE_PREF, 0);
  }

  public static void setLastVersionCode(Context context, int versionCode) throws IOException {
    if (!setIntegerPrefrenceBlocking(context, LAST_VERSION_CODE_PREF, versionCode)) {
      throw new IOException("couldn't write version code to sharedpreferences");
    }
  }

  public static boolean isFirstRun(Context context) {
    return getBooleanPreference(context, IS_FIRST_RUN, true);
  }

  public static void setFirstRun(Context context) {
    setBooleanPreference(context, IS_FIRST_RUN, false);
  }

  public static String getTheme(Context context) {
    return getStringPreference(context, THEME_PREF, "light");
  }

  public static boolean isVerifying(Context context) {
    return getBooleanPreference(context, VERIFYING_STATE_PREF, false);
  }

  public static void setVerifying(Context context, boolean verifying) {
    setBooleanPreference(context, VERIFYING_STATE_PREF, verifying);
  }

  public static boolean isPassphraseTimeoutEnabled(Context context) {
    return getBooleanPreference(context, PASSPHRASE_TIMEOUT_PREF, false);
  }

  public static int getPassphraseTimeoutInterval(Context context) {
    return getIntegerPreference(context, PASSPHRASE_TIMEOUT_INTERVAL_PREF, 5 * 60);
  }

  public static void setPassphraseTimeoutInterval(Context context, int interval) {
    setIntegerPrefrence(context, PASSPHRASE_TIMEOUT_INTERVAL_PREF, interval);
  }

  public static String getLanguage(Context context) {
    return getStringPreference(context, LANGUAGE_PREF, "zz");
  }

  public static void setLanguage(Context context, String language) {
    setStringPreference(context, LANGUAGE_PREF, language);
  }

  public static boolean isSmsDeliveryReportsEnabled(Context context) {
    return getBooleanPreference(context, SMS_DELIVERY_REPORT_PREF, false);
  }

  public static boolean isSmsDeliveryReportsToastEnabled(Context context) {
    return getBooleanPreference(context, SMS_DELIVERY_REPORT_TOAST_PREF, false);
  }

  public static boolean hasPromptedDefaultSmsProvider(Context context) {
    return getBooleanPreference(context, PROMPTED_DEFAULT_SMS_PREF, false);
  }

  public static void setPromptedDefaultSmsProvider(Context context, boolean value) {
    setBooleanPreference(context, PROMPTED_DEFAULT_SMS_PREF, value);
  }

  public static boolean isInterceptAllMmsEnabled(Context context) {
    return getBooleanPreference(context, ALL_MMS_PREF, true);
  }

  public static boolean isInterceptAllSmsEnabled(Context context) {
    return getBooleanPreference(context, ALL_SMS_PREF, true);
  }

  public static boolean isNotificationsEnabled(Context context) {
    return getBooleanPreference(context, NOTIFICATION_PREF, true);
  }

  public static String getNotificationRingtone(Context context) {
    return getStringPreference(context, RINGTONE_PREF, Settings.System.DEFAULT_NOTIFICATION_URI.toString());
  }

  public static boolean isNotificationVibrateEnabled(Context context) {
    return getBooleanPreference(context, VIBRATE_PREF, true);
  }

  public static String getNotificationLedColor(Context context) {
    return getStringPreference(context, LED_COLOR_PREF, "green");
  }

  public static String getNotificationLedPattern(Context context) {
    return getStringPreference(context, LED_BLINK_PREF, "500,2000");
  }

  public static String getNotificationLedPatternCustom(Context context) {
    return getStringPreference(context, LED_BLINK_PREF_CUSTOM, "500,2000");
  }

  public static void setNotificationLedPatternCustom(Context context, String pattern) {
    setStringPreference(context, LED_BLINK_PREF_CUSTOM, pattern);
  }

  public static boolean isThreadLengthTrimmingEnabled(Context context) {
    return getBooleanPreference(context, THREAD_TRIM_ENABLED, false);
  }

  public static int getThreadTrimLength(Context context) {
    return Integer.parseInt(getStringPreference(context, THREAD_TRIM_LENGTH, "500"));
  }

  public static boolean isMediaDownloadAllowed(Context context) {
    return getBooleanPreference(context, MEDIA_DOWNLOAD_PREF, true);
  }

  public static boolean isRoamingMediaDownloadAllowed(Context context) {
    return getBooleanPreference(context, MEDIA_DOWNLOAD_ROAMING_PREF, false);
  }

  public static boolean isEmojiDrawerDisabled(Context context) {
    return getBooleanPreference(context, DISABLE_EMOJI_DRAWER, false);
  }

  public static boolean showSentTime(Context context) {
    return getBooleanPreference(context, SHOW_SENT_TIME, false);
  }

  public static void setBooleanPreference(Context context, String key, boolean value) {
    PreferenceManager.getDefaultSharedPreferences(context).edit().putBoolean(key, value).apply();
  }

  public static boolean getBooleanPreference(Context context, String key, boolean defaultValue) {
    return PreferenceManager.getDefaultSharedPreferences(context).getBoolean(key, defaultValue);
  }

  public static void setStringPreference(Context context, String key, String value) {
    PreferenceManager.getDefaultSharedPreferences(context).edit().putString(key, value).apply();
  }

  public static String getStringPreference(Context context, String key, String defaultValue) {
    return PreferenceManager.getDefaultSharedPreferences(context).getString(key, defaultValue);
  }

  private static int getIntegerPreference(Context context, String key, int defaultValue) {
    return PreferenceManager.getDefaultSharedPreferences(context).getInt(key, defaultValue);
  }

  private static void setIntegerPrefrence(Context context, String key, int value) {
    PreferenceManager.getDefaultSharedPreferences(context).edit().putInt(key, value).apply();
  }

  private static boolean setIntegerPrefrenceBlocking(Context context, String key, int value) {
    return PreferenceManager.getDefaultSharedPreferences(context).edit().putInt(key, value).commit();
  }

  private static long getLongPreference(Context context, String key, long defaultValue) {
    return PreferenceManager.getDefaultSharedPreferences(context).getLong(key, defaultValue);
  }

  private static void setLongPreference(Context context, String key, long value) {
    PreferenceManager.getDefaultSharedPreferences(context).edit().putLong(key, value).apply();
  }
}
