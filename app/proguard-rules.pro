# ProGuard & R8 Configuration for KotSafe Enterprise
# Anti-Reverse-Engineering, Bytecode Obfuscation & Size Optimization

-keepattributes LineNumberTable,SourceFile,Signature,*Annotation*,InnerClasses,EnclosingMethod
-renamesourcefileattribute SourceFile

# Keep JNI classes in original packages (required by libcapture.so)
-allowaccessmodification

# Optimization passes
-optimizationpasses 3
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*

# Keep all native JNI method bindings
-keepclasseswithmembernames class * {
    native <methods>;
}

# JNI Bridge classes required by native C/C++ libpcapd.so and libcapture.so
-keep class com.kotsafe.security.engine.** {
    *;
}

-keep class com.kotsafe.security.CaptureService {

    native <methods>;
    public void dumpMasterSecret(byte[]);
    public boolean hasSeenDumpExtensions();
    public static void askStatsDump();
    *;
}

-keep class com.kotsafe.security.Blacklists** {
    *;
}

-keep class com.kotsafe.security.ConnectionsRegister** {
    *;
}

-keep class com.kotsafe.security.ZstdDecoder {
    native <methods>;
    *;
}

-keep class com.kotsafe.security.AppsResolver {
    *;
}

-keep class com.kotsafe.security.model.CaptureStats {
    *;
}

-keep class com.kotsafe.security.model.MatchList$ListDescriptor {
    *;
}

# Keep Gson serialization models and metadata
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keep class com.google.gson.** { *; }
-keep class com.kotsafe.security.model.** { *; }

# Keep 3rd-party binary parsers & MITM
-keep class com.pcapdroid.mitm.** { *; }
-keep class com.maxmind.db.** { *; }

# Keep ZXing QR Code generator & Google Play Code Scanner
-keep class com.google.zxing.** { *; }
-keep class com.google.mlkit.vision.codescanner.** { *; }

# Obfuscate all core detection engines, Yara rules, heuristic analyzers, AI clients, and internal business logic!