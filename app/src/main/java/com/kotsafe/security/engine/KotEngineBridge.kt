package com.kotsafe.security.engine

/**
 * Clean-Room Native Bridge for KotEngine.
 *
 * Provides a high-performance C11 packet capture, forwarding, inspection,
 * threat detection, JA4 fingerprinting, and Shannon entropy analysis bridge.
 * 100% clean-room proprietary implementation with zero GPL runtime dependencies.
 */
class KotEngineBridge {

    var listener: ((Array<ConnInfo>) -> Unit)? = null
    var threatListener: ((ThreatAlert) -> Unit)? = null

    /**
     * Set by VpnService to VpnService::protect - called from native forwarder
     * before each UDP backing socket is used, preventing routing loop.
     */
    var protectDelegate: ((Int) -> Boolean)? = null

    /**
     * Set by VpnService to resolve connection owner UID synchronously.
     */
    var uidResolverDelegate: ((Int, String, Int, String, Int) -> Int)? = null

    @Suppress("unused")
    private fun protect(fd: Int): Boolean = protectDelegate?.invoke(fd) ?: false

    @Suppress("unused")
    private fun resolveUid(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): Int =
        uidResolverDelegate?.invoke(proto, srcIp, srcPort, dstIp, dstPort) ?: -1

    @Suppress("unused")
    private fun onThreatAlert(type: Int, uid: Int, details: String, timestampMs: Long) {
        threatListener?.invoke(ThreatAlert(type, uid, details, timestampMs))
    }

    @Suppress("unused")
    private fun onConnectionsUpdated(conns: Array<ConnInfo>) {
        listener?.invoke(conns)
    }

    fun init(
        maxConnections: Int = 8192,
        idleTimeoutSecs: Int = 120,
        logRingCapacity: Int = 1024,
        snaplen: Int = 0,
        resolveUid: Boolean = true,
        payloadMode: Int = 1
    ): Int = nativeInit(maxConnections, idleTimeoutSecs, logRingCapacity, snaplen, resolveUid, payloadMode)

    fun startCapture(tunFd: Int): Int = nativeStartCapture(tunFd)
    fun stopCapture() = nativeStopCapture()
    fun setPcapDump(path: String?): Int = nativeSetPcapDump(path)
    fun blacklistAdd(addr: ByteArray, family: Int, prefixLen: Int) = nativeBlacklistAdd(addr, family, prefixLen)
    fun blacklistClear(family: Int) = nativeBlacklistClear(family)

    /** Returns [pktsSent, bytesSent, pktsRcvd, bytesRcvd, blockedPkts, parseErrors, activeConnections, totalConnections, dnsQueries] */
    fun getStats(): LongArray = nativeGetStats()

    fun destroy() = nativeDestroy()

    fun getPayload(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, dir: Int = 0): ByteArray? =
        nativeGetPayload(proto, srcIp, srcPort, dstIp, dstPort, dir)

    fun startStreamServer(port: Int = 8080): Int = nativeStartStreamServer(port)
    fun stopStreamServer() = nativeStopStreamServer()

    fun setPrivateDnsBlocked(blocked: Boolean) = nativeSetPrivateDnsBlocked(blocked)
    fun setCustomDns(dnsIp: String?): Int = nativeSetCustomDns(dnsIp)
    fun setLanBlockedUids(uids: IntArray?) = nativeSetLanBlockedUids(uids)

    /** Configures Android app UIDs completely blocked from internet access */
    fun setBlockedUids(uids: IntArray?) = nativeSetBlockedUids(uids)

    /** Adds domain to native active firewall blocklist (triggers DNS sinkholing) */
    fun addBlockedDomain(domain: String) = nativeAddBlockedDomain(domain)

    /** Removes domain from native active firewall blocklist */
    fun removeBlockedDomain(domain: String) = nativeRemoveBlockedDomain(domain)

    /** Clears all blocked domains from native active firewall */
    fun clearBlockedDomains() = nativeClearBlockedDomains()

    /** Reverse DNS lookup from learned DNS answers */
    fun lookupDnsCache(ip: String): String? = nativeLookupDnsCache(ip)

    fun addProxyRule(origPort: Int, targetIp: String, targetPort: Int): Int =
        nativeAddProxyRule(origPort, targetIp, targetPort)
    fun removeProxyRule(origPort: Int): Int = nativeRemoveProxyRule(origPort)
    fun setProxyExemptUid(uid: Int) = nativeSetProxyExemptUid(uid)
    fun setSocks5Proxy(proxyIp: String?, proxyPort: Int): Int = nativeSetSocks5Proxy(proxyIp, proxyPort)

    fun addTlsSecret(keylogLine: String): Int = nativeAddTlsSecret(keylogLine)

    /** Returns DoubleArray of [txSpeedBps, rxSpeedBps] */
    fun getConnSpeed(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): DoubleArray =
        nativeGetConnSpeed(proto, srcIp, srcPort, dstIp, dstPort)

    /** Fast native Shannon Entropy calculation (0.0 to 8.0 bits per byte) */
    fun calculateEntropy(data: ByteArray): Float = nativeCalculateEntropy(data)

    /**
     * Comprehensive Shannon Entropy Analysis.
     * Returns FloatArray: [entropy (0.0-8.0), is_encrypted (1.0/0.0), is_suspicious (1.0/0.0), byte_count]
     */
    fun analyzeEntropy(data: ByteArray): FloatArray? = nativeAnalyzeEntropy(data)

    /** Fast native JA4 fingerprint generation */
    fun generateJa4(
        isQuic: Boolean,
        tlsVersion: Int,
        hasSni: Boolean,
        ciphers: IntArray,
        extensions: IntArray,
        alpn: String?
    ): String? = nativeGenerateJa4(isQuic, tlsVersion, hasSni, ciphers, extensions, alpn)

    private external fun nativeInit(
        maxConnections: Int, idleTimeoutSecs: Int, logRingCapacity: Int,
        snaplen: Int, resolveUid: Boolean, payloadMode: Int
    ): Int
    private external fun nativeStartCapture(tunFd: Int): Int
    private external fun nativeStopCapture()
    private external fun nativeSetPcapDump(path: String?): Int
    private external fun nativeBlacklistAdd(addr: ByteArray, family: Int, prefixLen: Int)
    private external fun nativeBlacklistClear(family: Int)
    private external fun nativeGetStats(): LongArray
    private external fun nativeGetPayload(
        proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, dir: Int
    ): ByteArray?
    private external fun nativeStartStreamServer(port: Int): Int
    private external fun nativeStopStreamServer()
    private external fun nativeSetPrivateDnsBlocked(blocked: Boolean)
    private external fun nativeSetCustomDns(dnsIp: String?): Int
    private external fun nativeSetLanBlockedUids(uids: IntArray?)
    private external fun nativeSetBlockedUids(uids: IntArray?)
    private external fun nativeAddBlockedDomain(domain: String)
    private external fun nativeRemoveBlockedDomain(domain: String)
    private external fun nativeClearBlockedDomains()
    private external fun nativeLookupDnsCache(ip: String): String?
    private external fun nativeAddProxyRule(origPort: Int, targetIp: String, targetPort: Int): Int
    private external fun nativeRemoveProxyRule(origPort: Int): Int
    private external fun nativeSetProxyExemptUid(uid: Int)
    private external fun nativeSetSocks5Proxy(proxyIp: String?, proxyPort: Int): Int
    private external fun nativeAddTlsSecret(keylogLine: String): Int
    private external fun nativeGetConnSpeed(
        proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int
    ): DoubleArray
    private external fun nativeCalculateEntropy(data: ByteArray): Float
    private external fun nativeAnalyzeEntropy(data: ByteArray): FloatArray?
    private external fun nativeGenerateJa4(
        isQuic: Boolean, tlsVersion: Int, hasSni: Boolean,
        ciphers: IntArray, extensions: IntArray, alpn: String?
    ): String?
    private external fun nativeDestroy()

    companion object {
        init {
            try {
                System.loadLibrary("kotengine")
            } catch (e: UnsatisfiedLinkError) {
                // In test environments or when library fails to load
            }
        }

        private var sInstance: KotEngineBridge? = null

        @JvmStatic
        @Synchronized
        fun getInstance(): KotEngineBridge {
            if (sInstance == null) {
                sInstance = KotEngineBridge()
            }
            return sInstance!!
        }
    }
}
