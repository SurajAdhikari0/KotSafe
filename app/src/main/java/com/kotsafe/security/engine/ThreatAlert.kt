package com.kotsafe.security.engine

/**
 * Threat alert notification passed across JNI from KotEngine native detector.
 */
data class ThreatAlert(
    val type: Int,
    val uid: Int,
    val details: String,
    val timestampMs: Long
)
