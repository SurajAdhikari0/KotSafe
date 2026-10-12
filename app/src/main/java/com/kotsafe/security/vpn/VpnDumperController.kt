/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.vpn

import android.content.Context
import android.net.Uri
import com.kotsafe.security.Log
import com.kotsafe.security.interfaces.PcapDumper
import com.kotsafe.security.model.CaptureSettings
import com.kotsafe.security.model.Prefs
import com.kotsafe.security.pcap_dump.FileDumper
import com.kotsafe.security.pcap_dump.HTTPServer
import com.kotsafe.security.pcap_dump.TCPDumper
import com.kotsafe.security.pcap_dump.UDPDumper
import java.io.IOException
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingDeque

fun interface ErrorCallback {
    fun onError(msg: String)
}

/**
 * Clean-room Kotlin PCAP Dumper Controller for KotSafe VPN Service.
 * Dispatches captured packet buffers to configured dump sinks (File, HTTP, TCP, UDP)
 * using an asynchronous bounded queue and dedicated worker thread.
 */
class VpnDumperController(
    private val context: Context,
    private val settings: CaptureSettings,
    private val pcapUri: Uri?,
    private val onError: ErrorCallback,
    private val onFatalStopNeeded: Runnable
) {
    companion object {
        private const val TAG = "VpnDumperController"
        private const val DUMP_QUEUE_MAX = 512
    }

    private var dumper: PcapDumper? = null
    private var dumperThread: Thread? = null
    private val dumpQueue = LinkedBlockingDeque<ByteArray>(DUMP_QUEUE_MAX)

    val dumperBpf: String
        get() = dumper?.bpf ?: ""

    fun initializeDumper(collectorAddress: InetSocketAddress?) {
        dumper = when (settings.dump_mode) {
            Prefs.DumpMode.HTTP_SERVER -> HTTPServer(context, settings.http_server_port, settings.pcapng_format)
            Prefs.DumpMode.PCAP_FILE -> if (pcapUri != null) FileDumper(context, pcapUri) else null
            Prefs.DumpMode.UDP_EXPORTER -> if (collectorAddress != null) UDPDumper(collectorAddress, settings.pcapng_format) else null
            Prefs.DumpMode.TCP_EXPORTER -> if (collectorAddress != null) TCPDumper(collectorAddress, settings.pcapng_format) else null
            else -> null
        }
    }

    fun start() {
        if (dumper == null) return

        dumperThread = Thread({ runDumperLoop() }, "KotSafe-DumperThread").apply {
            start()
        }
    }

    private fun runDumperLoop() {
        val activeDumper = dumper ?: return
        Log.d(TAG, "Starting the dumper")

        try {
            activeDumper.startDumper()
        } catch (e: Exception) {
            Log.e(TAG, "Error starting dumper: $e")
            onError.onError(e.localizedMessage ?: "Dumper start error")
            onFatalStopNeeded.run()
            return
        }

        Log.d(TAG, "Dumper running")

        while (true) {
            val data: ByteArray = try {
                dumpQueue.take()
            } catch (e: InterruptedException) {
                continue
            }

            if (data.isEmpty()) { // Termination marker
                break
            }

            try {
                activeDumper.dumpData(data)
            } catch (e: IOException) {
                Log.e(TAG, "Error dumping data: $e")
                onError.onError(e.localizedMessage ?: "Dumper write error")
                onFatalStopNeeded.run()
                break
            }
        }

        try {
            activeDumper.stopDumper()
        } catch (e: IOException) {
            Log.e(TAG, "Error stopping dumper: $e")
        }
    }

    fun dumpPcapData(data: ByteArray) {
        if (dumper != null && data.isNotEmpty()) {
            while (true) {
                try {
                    dumpQueue.put(data)
                    break
                } catch (ignored: InterruptedException) {
                }
            }
        }
    }

    fun stop() {
        if (dumperThread?.isAlive == true) {
            dumpQueue.offer(ByteArray(0))
        }
    }

    fun join(timeoutMs: Long = 2000L) {
        stop()
        dumperThread?.let { thread ->
            if (thread.isAlive) {
                try {
                    thread.join(timeoutMs)
                } catch (ignored: InterruptedException) {
                    stop()
                }
            }
        }
        dumperThread = null
        dumper = null
        dumpQueue.clear()
    }
}
