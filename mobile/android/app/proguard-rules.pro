# Add project specific ProGuard rules here.

# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** { kotlinx.serialization.json.JsonObject ***; }
-keep,includedescriptorclasses class com.agentmessenger.android.data.**$$serializer { *; }
-keepclassmembers class com.agentmessenger.android.data.** { *** Companion; }
-keepclasseswithmembers class com.agentmessenger.android.data.** { kotlinx.serialization.KSerializer serializer(...); }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**