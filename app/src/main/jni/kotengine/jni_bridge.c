/*
 * KotEngine Clean-Room Native Bridge
 * Copyright (C) 2026 KotSafe Security Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "capture_engine.h"
#include "entropy.h"
#include "ja4.h"

typedef struct {
    JavaVM *jvm;
    jobject bridge_obj;       /* global ref to the Java KotEngineBridge instance */
    jmethodID on_conn_update; /* void onConnectionsUpdated(ConnInfo[] conns) */
    jmethodID on_threat_alert;/* void onThreatAlert(int type, int uid, String details, long timestampMs) */
    jclass conn_info_class;
    jmethodID conn_info_ctor; /* ConnInfo(...) */
    jmethodID protect_fd;     /* boolean protect(int fd) - VpnService.protect() */
    jmethodID resolve_uid;    /* int resolveUid(int proto, String srcIp, int srcPort, String dstIp, int dstPort) */
    netcap_engine_t *engine;
    netcap_forward_engine_t *fwd;
} bridge_ctx_t;

static bridge_ctx_t g_ctx;

static void ip_to_string(const uint8_t *addr, uint8_t family, char *out, size_t out_sz) {
    if (family == 4) {
        snprintf(out, out_sz, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else {
        snprintf(out, out_sz,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    }
}

static void on_threat_alert_upcall(const netcap_threat_alert_t *alert, void *user_data) {
    (void)user_data;
    if (!alert || !g_ctx.bridge_obj || !g_ctx.on_threat_alert) return;

    JNIEnv *env;
    int attached = 0;
    if ((*g_ctx.jvm)->GetEnv(g_ctx.jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_ctx.jvm)->AttachCurrentThread(g_ctx.jvm, &env, NULL) != 0) return;
        attached = 1;
    }

    jstring jdetails = (*env)->NewStringUTF(env, alert->details[0] ? alert->details : "");
    (*env)->CallVoidMethod(env, g_ctx.bridge_obj, g_ctx.on_threat_alert,
                           (jint)alert->type, (jint)alert->uid, jdetails, (jlong)alert->timestamp_ms);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    (*env)->DeleteLocalRef(env, jdetails);

    if (attached) (*g_ctx.jvm)->DetachCurrentThread(g_ctx.jvm);
}

static int32_t resolve_uid_upcall(uint8_t proto, const char *src_ip, uint16_t src_port,
                                  const char *dst_ip, uint16_t dst_port, void *user_data) {
    (void)user_data;
    if (!g_ctx.bridge_obj || !g_ctx.resolve_uid) return -1;
    JNIEnv *env;
    if ((*g_ctx.jvm)->GetEnv(g_ctx.jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_ctx.jvm)->AttachCurrentThread(g_ctx.jvm, &env, NULL) != 0) return -1;
    }
    jstring jsrc = (*env)->NewStringUTF(env, src_ip);
    jstring jdst = (*env)->NewStringUTF(env, dst_ip);
    jint uid = (*env)->CallIntMethod(env, g_ctx.bridge_obj, g_ctx.resolve_uid,
                                     (jint)proto, jsrc, (jint)src_port, jdst, (jint)dst_port);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        uid = -1;
    }
    if (jsrc) (*env)->DeleteLocalRef(env, jsrc);
    if (jdst) (*env)->DeleteLocalRef(env, jdst);
    return (int32_t)uid;
}

static void on_conn_update(const netcap_conn_t *const *conns, uint32_t count, void *user_data) {
    (void)user_data;
    if (count == 0 || !g_ctx.bridge_obj || !g_ctx.on_conn_update || !g_ctx.conn_info_class || !g_ctx.conn_info_ctor) return;

    JNIEnv *env;
    int attached = 0;
    if ((*g_ctx.jvm)->GetEnv(g_ctx.jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_ctx.jvm)->AttachCurrentThread(g_ctx.jvm, &env, NULL) != 0) return;
        attached = 1;
    }

    jobjectArray arr = (*env)->NewObjectArray(env, count, g_ctx.conn_info_class, NULL);
    if (!arr) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        if (attached) (*g_ctx.jvm)->DetachCurrentThread(g_ctx.jvm);
        return;
    }

    char src_buf[48], dst_buf[48];

    for (uint32_t i = 0; i < count; i++) {
        const netcap_conn_t *c = conns[i];
        if (!c) continue;
        ip_to_string(c->key.src_ip, c->key.family, src_buf, sizeof(src_buf));
        ip_to_string(c->key.dst_ip, c->key.family, dst_buf, sizeof(dst_buf));

        jstring jsrc = (*env)->NewStringUTF(env, src_buf);
        jstring jdst = (*env)->NewStringUTF(env, dst_buf);
        jstring jdom = (*env)->NewStringUTF(env, c->domain_name[0] ? c->domain_name : "");
        jstring jl7  = (*env)->NewStringUTF(env, c->l7_proto[0] ? c->l7_proto : "");
        jstring jcc  = (*env)->NewStringUTF(env, c->country_code[0] ? c->country_code : "");
        jstring jja4 = (*env)->NewStringUTF(env, c->ja4[0] ? c->ja4 : "");

        jobject obj = (*env)->NewObject(env, g_ctx.conn_info_class, g_ctx.conn_info_ctor,
                                         (jint)c->key.proto, jsrc, (jint)c->key.src_port,
                                         jdst, (jint)c->key.dst_port,
                                         (jlong)c->bytes_sent, (jlong)c->bytes_rcvd,
                                         (jint)c->uid, (jint)c->tcp_state,
                                         jdom, jl7, jcc,
                                         (jdouble)c->tx_bps, (jdouble)c->rx_bps,
                                         jja4, (jfloat)c->entropy);
        if (obj) {
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, obj);
        }
        if (jsrc) (*env)->DeleteLocalRef(env, jsrc);
        if (jdst) (*env)->DeleteLocalRef(env, jdst);
        if (jdom) (*env)->DeleteLocalRef(env, jdom);
        if (jl7) (*env)->DeleteLocalRef(env, jl7);
        if (jcc) (*env)->DeleteLocalRef(env, jcc);
        if (jja4) (*env)->DeleteLocalRef(env, jja4);
    }

    (*env)->CallVoidMethod(env, g_ctx.bridge_obj, g_ctx.on_conn_update, arr);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, arr);

    if (attached) (*g_ctx.jvm)->DetachCurrentThread(g_ctx.jvm);
}

static int protect_fd_upcall(int fd, void *user_data) {
    (void)user_data;
    JNIEnv *env;
    int attached = 0;
    if ((*g_ctx.jvm)->GetEnv(g_ctx.jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_ctx.jvm)->AttachCurrentThread(g_ctx.jvm, &env, NULL) != 0) return -1;
        attached = 1;
    }
    jboolean ok = (*env)->CallBooleanMethod(env, g_ctx.bridge_obj, g_ctx.protect_fd, (jint)fd);
    if (attached) (*g_ctx.jvm)->DetachCurrentThread(g_ctx.jvm);
    return ok ? 0 : -1;
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeInit(JNIEnv *env, jobject thiz,
                                                            jint maxConnections, jint idleTimeoutSecs,
                                                            jint logRingCapacity, jint snaplen,
                                                            jboolean resolveUid, jint payloadMode) {
    (*env)->GetJavaVM(env, &g_ctx.jvm);
    g_ctx.bridge_obj = (*env)->NewGlobalRef(env, thiz);

    jclass bridge_class = (*env)->GetObjectClass(env, thiz);
    g_ctx.on_conn_update = (*env)->GetMethodID(env, bridge_class, "onConnectionsUpdated",
                                                "([Lcom/kotsafe/security/engine/ConnInfo;)V");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    g_ctx.on_threat_alert = (*env)->GetMethodID(env, bridge_class, "onThreatAlert",
                                                 "(IILjava/lang/String;J)V");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    jclass conn_info_local = (*env)->FindClass(env, "com/kotsafe/security/engine/ConnInfo");
    if (!conn_info_local) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -2;
    }
    g_ctx.conn_info_class = (jclass)(*env)->NewGlobalRef(env, conn_info_local);
    (*env)->DeleteLocalRef(env, conn_info_local);

    g_ctx.conn_info_ctor = (*env)->GetMethodID(env, g_ctx.conn_info_class, "<init>",
                                                "(ILjava/lang/String;ILjava/lang/String;IJJIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;DDLjava/lang/String;F)V");
    if ((*env)->ExceptionCheck(env) || !g_ctx.conn_info_ctor) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -3;
    }

    g_ctx.protect_fd = (*env)->GetMethodID(env, bridge_class, "protect", "(I)Z");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    g_ctx.resolve_uid = (*env)->GetMethodID(env, bridge_class, "resolveUid",
                                            "(ILjava/lang/String;ILjava/lang/String;I)I");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    netcap_engine_config_t cfg = {
        .max_connections = (uint32_t)maxConnections,
        .idle_timeout_secs = (uint32_t)idleTimeoutSecs,
        .log_ring_capacity = (uint32_t)logRingCapacity,
        .snaplen = (uint32_t)snaplen,
        .enable_uid_resolution = resolveUid ? 1 : 0,
        .payload_mode = (uint8_t)payloadMode,
    };
    g_ctx.engine = netcap_engine_create(&cfg);
    if (g_ctx.engine) {
        netcap_engine_set_threat_callback(g_ctx.engine, on_threat_alert_upcall, NULL);
        netcap_engine_set_uid_resolver(g_ctx.engine, resolve_uid_upcall, NULL);
    }
    return g_ctx.engine ? 0 : -1;
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeStartCapture(JNIEnv *env, jobject thiz, jint tunFd) {
    (void)env; (void)thiz;
    if (!g_ctx.engine) return -1;

    g_ctx.fwd = netcap_forward_create((int)tunFd);
    if (g_ctx.fwd) {
        netcap_forward_set_protect_cb(g_ctx.fwd, protect_fd_upcall, NULL);
        netcap_engine_attach_forward(g_ctx.engine, g_ctx.fwd);
    }

    return netcap_engine_start(g_ctx.engine, (int)tunFd, on_conn_update, NULL);
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeStopCapture(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    if (g_ctx.engine) netcap_engine_stop(g_ctx.engine);
    if (g_ctx.fwd) { netcap_forward_destroy(g_ctx.fwd); g_ctx.fwd = NULL; netcap_engine_attach_forward(g_ctx.engine, NULL); }
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetPcapDump(JNIEnv *env, jobject thiz, jstring path) {
    (void)thiz;
    if (!g_ctx.engine) return -1;
    if (path == NULL) return netcap_engine_set_pcap_dump(g_ctx.engine, NULL);
    const char *cpath = (*env)->GetStringUTFChars(env, path, NULL);
    int rc = netcap_engine_set_pcap_dump(g_ctx.engine, cpath);
    (*env)->ReleaseStringUTFChars(env, path, cpath);
    return rc;
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeBlacklistAdd(JNIEnv *env, jobject thiz,
                                                                   jbyteArray addr, jint family, jint prefixLen) {
    (void)thiz;
    if (!g_ctx.engine) return;
    jbyte *bytes = (*env)->GetByteArrayElements(env, addr, NULL);
    netcap_blacklist_add(netcap_engine_get_blacklist(g_ctx.engine),
                          (const uint8_t *)bytes, (uint8_t)family, (uint8_t)prefixLen);
    (*env)->ReleaseByteArrayElements(env, addr, bytes, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeBlacklistClear(JNIEnv *env, jobject thiz, jint family) {
    (void)env; (void)thiz;
    if (g_ctx.engine) netcap_blacklist_remove_all(netcap_engine_get_blacklist(g_ctx.engine), (uint8_t)family);
}

JNIEXPORT jlongArray JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeGetStats(JNIEnv *env, jobject thiz) {
    (void)thiz;
    netcap_engine_stats_t s = {0};
    if (g_ctx.engine) netcap_engine_get_stats(g_ctx.engine, &s);
    jlongArray out = (*env)->NewLongArray(env, 9);
    jlong vals[9] = {
        (jlong)s.pkts_sent,
        (jlong)s.bytes_sent,
        (jlong)s.pkts_rcvd,
        (jlong)s.bytes_rcvd,
        (jlong)s.blocked_pkts,
        (jlong)s.parse_errors,
        (jlong)s.active_connections,
        (jlong)s.total_connections,
        (jlong)s.dns_queries
    };
    (*env)->SetLongArrayRegion(env, out, 0, 9, vals);
    return out;
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeDestroy(JNIEnv *env, jobject thiz) {
    (void)thiz;
    if (g_ctx.engine) {
        netcap_engine_destroy(g_ctx.engine);
        g_ctx.engine = NULL;
    }
    if (g_ctx.fwd) {
        netcap_forward_destroy(g_ctx.fwd);
        g_ctx.fwd = NULL;
    }
    if (g_ctx.bridge_obj) { (*env)->DeleteGlobalRef(env, g_ctx.bridge_obj); g_ctx.bridge_obj = NULL; }
    if (g_ctx.conn_info_class) { (*env)->DeleteGlobalRef(env, g_ctx.conn_info_class); g_ctx.conn_info_class = NULL; }
}

JNIEXPORT jbyteArray JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeGetPayload(JNIEnv *env, jobject thiz,
                                                                 jint proto, jstring srcIp, jint srcPort,
                                                                 jstring dstIp, jint dstPort, jint dir) {
    (void)thiz;
    if (!g_ctx.engine || !srcIp || !dstIp) return NULL;

    const char *c_src = (*env)->GetStringUTFChars(env, srcIp, NULL);
    const char *c_dst = (*env)->GetStringUTFChars(env, dstIp, NULL);

    netcap_flow_key_t key = {0};
    key.proto = (uint8_t)proto;
    key.src_port = (uint16_t)srcPort;
    key.dst_port = (uint16_t)dstPort;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, c_src, &a4) == 1 && inet_pton(AF_INET, c_dst, &a4) == 1) {
        key.family = 4;
        inet_pton(AF_INET, c_src, key.src_ip);
        inet_pton(AF_INET, c_dst, key.dst_ip);
    } else if (inet_pton(AF_INET6, c_src, &a6) == 1 && inet_pton(AF_INET6, c_dst, &a6) == 1) {
        key.family = 6;
        inet_pton(AF_INET6, c_src, key.src_ip);
        inet_pton(AF_INET6, c_dst, key.dst_ip);
    }

    (*env)->ReleaseStringUTFChars(env, srcIp, c_src);
    (*env)->ReleaseStringUTFChars(env, dstIp, c_dst);

    uint8_t temp[32768];
    uint32_t len = netcap_engine_get_conn_payload(g_ctx.engine, &key, (int)dir, temp, sizeof(temp));
    if (len == 0) return NULL;

    jbyteArray res = (*env)->NewByteArray(env, (jsize)len);
    if (res) {
        (*env)->SetByteArrayRegion(env, res, 0, (jsize)len, (jbyte *)temp);
    }
    return res;
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeStartStreamServer(JNIEnv *env, jobject thiz, jint port) {
    (void)env; (void)thiz;
    if (!g_ctx.engine) return -1;
    return netcap_engine_start_stream_server(g_ctx.engine, (uint16_t)port);
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeStopStreamServer(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    if (g_ctx.engine) netcap_engine_stop_stream_server(g_ctx.engine);
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetPrivateDnsBlocked(JNIEnv *env, jobject thiz, jboolean blocked) {
    (void)env; (void)thiz;
    if (g_ctx.engine) {
        netcap_engine_set_private_dns_blocked(g_ctx.engine, (bool)blocked);
    }
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetCustomDns(JNIEnv *env, jobject thiz, jstring dnsIp) {
    (void)thiz;
    if (!g_ctx.engine) return -1;
    const char *c_dns = dnsIp ? (*env)->GetStringUTFChars(env, dnsIp, NULL) : NULL;
    int rc = netcap_engine_set_custom_dns(g_ctx.engine, c_dns);
    if (dnsIp && c_dns) (*env)->ReleaseStringUTFChars(env, dnsIp, c_dns);
    return rc;
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetLanBlockedUids(JNIEnv *env, jobject thiz, jintArray uids) {
    (void)thiz;
    if (!g_ctx.engine) return;
    if (!uids) {
        netcap_engine_set_lan_blocked_uids(g_ctx.engine, NULL, 0);
        return;
    }
    jsize len = (*env)->GetArrayLength(env, uids);
    jint *elems = (*env)->GetIntArrayElements(env, uids, NULL);
    if (elems) {
        netcap_engine_set_lan_blocked_uids(g_ctx.engine, (const int32_t *)elems, (size_t)len);
        (*env)->ReleaseIntArrayElements(env, uids, elems, JNI_ABORT);
    }
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeAddProxyRule(JNIEnv *env, jobject thiz,
                                                                   jint origPort, jstring targetIp, jint targetPort) {
    (void)thiz;
    if (!g_ctx.engine || !targetIp) return -1;
    const char *c_ip = (*env)->GetStringUTFChars(env, targetIp, NULL);
    int rc = netcap_engine_add_proxy_rule(g_ctx.engine, (uint16_t)origPort, c_ip, (uint16_t)targetPort);
    (*env)->ReleaseStringUTFChars(env, targetIp, c_ip);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeRemoveProxyRule(JNIEnv *env, jobject thiz, jint origPort) {
    (void)env; (void)thiz;
    if (!g_ctx.engine) return -1;
    return netcap_engine_remove_proxy_rule(g_ctx.engine, (uint16_t)origPort);
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetProxyExemptUid(JNIEnv *env, jobject thiz, jint uid) {
    (void)env; (void)thiz;
    if (g_ctx.engine) {
        netcap_engine_set_proxy_exempt_uid(g_ctx.engine, (int32_t)uid);
    }
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetSocks5Proxy(JNIEnv *env, jobject thiz,
                                                                      jstring proxyIp, jint proxyPort) {
    (void)thiz;
    if (!g_ctx.engine) return -1;
    const char *c_ip = NULL;
    if (proxyIp) c_ip = (*env)->GetStringUTFChars(env, proxyIp, NULL);
    int rc = netcap_engine_set_socks5_proxy(g_ctx.engine, c_ip, (uint16_t)proxyPort);
    if (proxyIp && c_ip) (*env)->ReleaseStringUTFChars(env, proxyIp, c_ip);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeAddTlsSecret(JNIEnv *env, jobject thiz, jstring keylogLine) {
    (void)thiz;
    if (!g_ctx.engine || !keylogLine) return -1;
    const char *c_line = (*env)->GetStringUTFChars(env, keylogLine, NULL);
    int rc = netcap_engine_add_tls_secret(g_ctx.engine, c_line);
    (*env)->ReleaseStringUTFChars(env, keylogLine, c_line);
    return rc;
}

JNIEXPORT jdoubleArray JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeGetConnSpeed(JNIEnv *env, jobject thiz,
                                                                   jint proto, jstring srcIp, jint srcPort,
                                                                   jstring dstIp, jint dstPort) {
    (void)thiz;
    jdoubleArray arr = (*env)->NewDoubleArray(env, 2);
    if (!arr || !g_ctx.engine || !srcIp || !dstIp) return arr;

    const char *c_src = (*env)->GetStringUTFChars(env, srcIp, NULL);
    const char *c_dst = (*env)->GetStringUTFChars(env, dstIp, NULL);

    netcap_flow_key_t key = {0};
    key.proto = (uint8_t)proto;
    key.src_port = (uint16_t)srcPort;
    key.dst_port = (uint16_t)dstPort;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, c_src, &a4) == 1 && inet_pton(AF_INET, c_dst, &a4) == 1) {
        key.family = 4;
        inet_pton(AF_INET, c_src, key.src_ip);
        inet_pton(AF_INET, c_dst, key.dst_ip);
    } else if (inet_pton(AF_INET6, c_src, &a6) == 1 && inet_pton(AF_INET6, c_dst, &a6) == 1) {
        key.family = 6;
        inet_pton(AF_INET6, c_src, key.src_ip);
        inet_pton(AF_INET6, c_dst, key.dst_ip);
    }
    (*env)->ReleaseStringUTFChars(env, srcIp, c_src);
    (*env)->ReleaseStringUTFChars(env, dstIp, c_dst);

    double tx_bps = 0.0, rx_bps = 0.0;
    netcap_engine_get_conn_speed(g_ctx.engine, &key, &tx_bps, &rx_bps);

    jdouble speeds[2] = { tx_bps, rx_bps };
    (*env)->SetDoubleArrayRegion(env, arr, 0, 2, speeds);
    return arr;
}

/* Shannon Entropy calculation */
JNIEXPORT jfloat JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeCalculateEntropy(JNIEnv *env, jobject thiz, jbyteArray data) {
    (void)thiz;
    if (!data) return 0.0f;
    jsize len = (*env)->GetArrayLength(env, data);
    if (len <= 0) return 0.0f;
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    float entropy = kotengine_calculate_entropy((const uint8_t *)bytes, (size_t)len);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    return (jfloat)entropy;
}

/* Comprehensive Shannon Entropy Analysis: returns [entropy, is_encrypted, is_suspicious, byte_count] */
JNIEXPORT jfloatArray JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeAnalyzeEntropy(JNIEnv *env, jobject thiz, jbyteArray data) {
    (void)thiz;
    jfloatArray out = (*env)->NewFloatArray(env, 4);
    if (!out) return NULL;
    if (!data) return out;
    jsize len = (*env)->GetArrayLength(env, data);
    if (len <= 0) return out;
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    kotengine_entropy_result_t res = kotengine_analyze_entropy((const uint8_t *)bytes, (size_t)len);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);

    jfloat vals[4] = {
        res.entropy,
        res.is_encrypted ? 1.0f : 0.0f,
        res.is_suspicious ? 1.0f : 0.0f,
        (jfloat)res.byte_count
    };
    (*env)->SetFloatArrayRegion(env, out, 0, 4, vals);
    return out;
}

/* JA4 TLS / QUIC Fingerprint generation */
JNIEXPORT jstring JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeGenerateJa4(JNIEnv *env, jobject thiz,
                                                                  jboolean isQuic, jint tlsVersion,
                                                                  jboolean hasSni, jintArray ciphers,
                                                                  jintArray extensions, jstring alpn) {
    (void)thiz;
    size_t num_ciphers = 0;
    uint16_t *ciphers_buf = NULL;
    if (ciphers) {
        jsize len = (*env)->GetArrayLength(env, ciphers);
        if (len > 0) {
            num_ciphers = (size_t)len;
            ciphers_buf = malloc(sizeof(uint16_t) * num_ciphers);
            jint *elems = (*env)->GetIntArrayElements(env, ciphers, NULL);
            for (size_t i = 0; i < num_ciphers; i++) {
                ciphers_buf[i] = (uint16_t)elems[i];
            }
            (*env)->ReleaseIntArrayElements(env, ciphers, elems, JNI_ABORT);
        }
    }

    size_t num_extensions = 0;
    uint16_t *extensions_buf = NULL;
    if (extensions) {
        jsize len = (*env)->GetArrayLength(env, extensions);
        if (len > 0) {
            num_extensions = (size_t)len;
            extensions_buf = malloc(sizeof(uint16_t) * num_extensions);
            jint *elems = (*env)->GetIntArrayElements(env, extensions, NULL);
            for (size_t i = 0; i < num_extensions; i++) {
                extensions_buf[i] = (uint16_t)elems[i];
            }
            (*env)->ReleaseIntArrayElements(env, extensions, elems, JNI_ABORT);
        }
    }

    const char *c_alpn = alpn ? (*env)->GetStringUTFChars(env, alpn, NULL) : NULL;

    kotengine_ja4_t res = kotengine_generate_ja4((bool)isQuic, (uint16_t)tlsVersion, (bool)hasSni,
                                                ciphers_buf, num_ciphers,
                                                extensions_buf, num_extensions,
                                                c_alpn);

    if (alpn && c_alpn) (*env)->ReleaseStringUTFChars(env, alpn, c_alpn);
    if (ciphers_buf) free(ciphers_buf);
    if (extensions_buf) free(extensions_buf);

    if (!res.valid) return NULL;
    return (*env)->NewStringUTF(env, res.ja4);
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeSetBlockedUids(JNIEnv *env, jobject thiz, jintArray uids) {
    (void)thiz;
    if (!g_ctx.engine) return;
    if (!uids) {
        netcap_engine_set_blocked_uids(g_ctx.engine, NULL, 0);
        return;
    }
    jsize len = (*env)->GetArrayLength(env, uids);
    jint *elems = (*env)->GetIntArrayElements(env, uids, NULL);
    if (elems) {
        netcap_engine_set_blocked_uids(g_ctx.engine, (const int32_t *)elems, (size_t)len);
        (*env)->ReleaseIntArrayElements(env, uids, elems, JNI_ABORT);
    }
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeAddBlockedDomain(JNIEnv *env, jobject thiz, jstring domain) {
    (void)thiz;
    if (!g_ctx.engine || !domain) return;
    const char *c_dom = (*env)->GetStringUTFChars(env, domain, NULL);
    if (c_dom) {
        netcap_engine_add_blocked_domain(g_ctx.engine, c_dom);
        (*env)->ReleaseStringUTFChars(env, domain, c_dom);
    }
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeRemoveBlockedDomain(JNIEnv *env, jobject thiz, jstring domain) {
    (void)thiz;
    if (!g_ctx.engine || !domain) return;
    const char *c_dom = (*env)->GetStringUTFChars(env, domain, NULL);
    if (c_dom) {
        netcap_engine_remove_blocked_domain(g_ctx.engine, c_dom);
        (*env)->ReleaseStringUTFChars(env, domain, c_dom);
    }
}

JNIEXPORT void JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeClearBlockedDomains(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    if (g_ctx.engine) {
        netcap_engine_clear_blocked_domains(g_ctx.engine);
    }
}

JNIEXPORT jstring JNICALL
Java_com_kotsafe_security_engine_KotEngineBridge_nativeLookupDnsCache(JNIEnv *env, jobject thiz, jstring ipStr) {
    (void)thiz;
    if (!g_ctx.engine || !ipStr) return NULL;
    const char *c_ip = (*env)->GetStringUTFChars(env, ipStr, NULL);
    if (!c_ip) return NULL;

    struct in_addr a4;
    struct in6_addr a6;
    uint8_t ip_bytes[16];
    uint8_t family = 0;

    if (inet_pton(AF_INET, c_ip, &a4) == 1) {
        family = 4;
        memcpy(ip_bytes, &a4.s_addr, 4);
    } else if (inet_pton(AF_INET6, c_ip, &a6) == 1) {
        family = 6;
        memcpy(ip_bytes, &a6.s6_addr, 16);
    }
    (*env)->ReleaseStringUTFChars(env, ipStr, c_ip);

    if (family == 0) return NULL;

    char domain_buf[256] = {0};
    if (netcap_engine_lookup_dns_cache(g_ctx.engine, ip_bytes, family, domain_buf, sizeof(domain_buf))) {
        return (*env)->NewStringUTF(env, domain_buf);
    }
    return NULL;
}
