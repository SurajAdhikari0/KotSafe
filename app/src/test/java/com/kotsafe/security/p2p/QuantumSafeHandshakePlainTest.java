package com.kotsafe.security;

import com.kotsafe.security.model.QuantumSafeHandshake;

import org.junit.Assert;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class QuantumSafeHandshakePlainTest {

    @org.junit.Before
    public void setUp() {
        com.kotsafe.security.KotSafe.isUnderTest = true;
    }

    @Test
    public void testQuantumHandshakeAgreement() throws Exception {
        PipedOutputStream s2c_out = new PipedOutputStream();
        PipedInputStream s2c_in = new PipedInputStream(s2c_out, 4096);

        PipedOutputStream c2s_out = new PipedOutputStream();
        PipedInputStream c2s_in = new PipedInputStream(c2s_out, 4096);

        ExecutorService pool = Executors.newFixedThreadPool(2);

        Callable<QuantumSafeHandshake.ServerResult> serverTask = () -> {
            DataInputStream serverIn = new DataInputStream(c2s_in);
            DataOutputStream serverOut = new DataOutputStream(s2c_out);
            return QuantumSafeHandshake.serverHandshake(serverIn, serverOut);
        };

        Callable<QuantumSafeHandshake.ClientResult> clientTask = () -> {
            DataInputStream clientIn = new DataInputStream(s2c_in);
            DataOutputStream clientOut = new DataOutputStream(c2s_out);
            return QuantumSafeHandshake.clientHandshake(clientIn, clientOut);
        };

        Future<QuantumSafeHandshake.ServerResult> serverFuture = pool.submit(serverTask);
        Future<QuantumSafeHandshake.ClientResult> clientFuture = pool.submit(clientTask);

        QuantumSafeHandshake.ServerResult serverResult = serverFuture.get();
        QuantumSafeHandshake.ClientResult clientResult = clientFuture.get();

        pool.shutdown();

        Assert.assertNotNull(serverResult);
        Assert.assertNotNull(clientResult);
        Assert.assertNotNull(serverResult.sessionKeyHex);
        Assert.assertEquals(64, serverResult.sessionKeyHex.length());
        Assert.assertEquals(serverResult.sessionKeyHex, clientResult.sessionKeyHex);
    }
}
