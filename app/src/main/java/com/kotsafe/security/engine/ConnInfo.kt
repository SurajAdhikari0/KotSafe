package com.kotsafe.security.engine

import androidx.annotation.Keep

/**
 * Clean-room Connection descriptor passed across JNI in batched arrays.
 */
@Keep
data class ConnInfo(
    val proto: Int,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val bytesSent: Long,
    val bytesRcvd: Long,
    val uid: Int,
    val tcpState: Int,
    val domain: String = "",
    val l7Proto: String = "",
    val countryCode: String = "",
    val txSpeedBps: Double = 0.0,
    val rxSpeedBps: Double = 0.0,
    val ja4: String = "",
    val entropy: Float = 0.0f
)
