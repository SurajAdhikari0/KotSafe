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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.pcap_dump;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Utils;
import com.kotsafe.security.interfaces.PcapDumper;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Iterator;

public class UDPDumper implements PcapDumper {
    private static final String TAG = "UDPDumper";
    private final InetSocketAddress mServer;
    private final boolean mPcapngFormat;
    private boolean mSendHeader;
    private DatagramSocket mSocket;

    public UDPDumper(InetSocketAddress server, boolean pcapngFormat) {
        mServer = server;
        mSendHeader = true;
        mPcapngFormat = pcapngFormat;
    }

    @Override
    public void startDumper() throws IOException {
        mSocket = new DatagramSocket();
        CaptureService.requireInstance().protect(mSocket);
    }

    @Override
    public void stopDumper() throws IOException {
        mSocket.close();
    }

    @Override
    public String getBpf() {
        return "not (host " + mServer.getAddress().getHostAddress() + " and udp port " + mServer.getPort() + ")";
    }

    private void sendDatagram(byte[] data, int offset, int len) throws IOException {
        DatagramPacket request = new DatagramPacket(data, offset, len, mServer);
        mSocket.send(request);
    }

    @Override
    public void dumpData(byte[] data) throws IOException {
        if(mSendHeader) {
            mSendHeader = false;

            byte[] hdr = CaptureService.getPcapHeader();
            sendDatagram(hdr, 0, hdr.length);
        }

        Iterator<Integer> it = Utils.iterPcapRecords(data, mPcapngFormat);
        int pos = 0;

        while(it.hasNext()) {
            int rec_len = it.next();
            sendDatagram(data, pos, rec_len);
            pos += rec_len;
        }
    }
}
