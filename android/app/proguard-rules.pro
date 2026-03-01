-keep class com.polymarket.watcher.** { *; }
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
