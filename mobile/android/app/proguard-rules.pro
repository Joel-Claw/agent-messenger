# Proguard rules for Agent Messenger
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-keep class kotlinx.serialization.** { *; }
-keep class com.agentmessenger.android.data.** { *; }
-dontwarn kotlinx.serialization.**