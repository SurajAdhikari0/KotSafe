package com.kotsafe.security.model;

import android.util.AtomicFile;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/** App-private advisory evidence cache, intentionally separate from firewall/hash databases. */
public final class IntelligenceSnapshotStore {
    private static final ConcurrentHashMap<String,Object> LOCKS = new ConcurrentHashMap<>();
    private final AtomicFile file;
    private final File lockFile;
    private final Object lock;
    private final IntelligenceManifestV2Verifier verifier;
    private long highWatermark;
    private IntelligenceManifestV2Verifier.Snapshot current;

    /** directory should be a tenant-specific directory beneath Context.getFilesDir(). */
    public IntelligenceSnapshotStore(File directory, IntelligenceManifestV2Verifier verifier) throws IOException {
        if (directory == null || !directory.isAbsolute() || verifier == null) throw new IOException("Explicit private cache directory required");
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("Cannot create intelligence cache directory");
        File target = new File(directory,"intelligence-v2.json");
        this.file=new AtomicFile(target);
        this.lockFile=new File(directory,"intelligence-v2.lock");
        this.lock=LOCKS.computeIfAbsent(target.getCanonicalPath(), key -> new Object());
        this.verifier=verifier;
    }

    public IntelligenceManifestV2Verifier.Snapshot install(byte[] envelope, long nowSeconds) throws IOException {
        synchronized (lock) {
            try (RandomAccessFile guard=new RandomAccessFile(lockFile,"rw"); FileLock ignored=guard.getChannel().lock()) {
                restoreLocked(nowSeconds);
                IntelligenceManifestV2Verifier.Snapshot next=verifier.verify(envelope,nowSeconds,highWatermark);
                FileOutputStream output=null;
                try {
                    output=file.startWrite(); output.write(envelope); output.flush(); output.getFD().sync();
                    file.finishWrite(output); output=null;
                } finally {
                    if (output!=null) file.failWrite(output);
                }
                current=next; highWatermark=next.version;
                return next;
            }
        }
    }

    public boolean restore(long nowSeconds) throws IOException {
        synchronized (lock) {
            try (RandomAccessFile guard=new RandomAccessFile(lockFile,"rw"); FileLock ignored=guard.getChannel().lock()) {
                return restoreLocked(nowSeconds);
            }
        }
    }

    private boolean restoreLocked(long nowSeconds) throws IOException {
        byte[] bytes;
        try (FileInputStream input=file.openRead()) { bytes=readBounded(input); }
        catch (FileNotFoundException missing) { return false; }
        IntelligenceManifestV2Verifier.Snapshot restored=verifier.restore(bytes,nowSeconds);
        if (restored.version<highWatermark) throw new IOException("Intelligence cache rollback detected");
        current=restored; highWatermark=restored.version; return true;
    }

    public long lastVersion() { synchronized(lock) { return highWatermark; } }

    public List<IntelligenceManifestV2Verifier.Indicator> active(long nowSeconds) {
        synchronized(lock) {
            if (current==null || nowSeconds<current.issuedAt || nowSeconds>=current.expiresAt) return Collections.emptyList();
            List<IntelligenceManifestV2Verifier.Indicator> result=new ArrayList<>();
            for (IntelligenceManifestV2Verifier.Indicator row:current.indicators)
                if (nowSeconds<row.validUntil) result.add(row);
            return Collections.unmodifiableList(result);
        }
    }

    static byte[] readBounded(java.io.InputStream input) throws IOException {
        ByteArrayOutputStream output=new ByteArrayOutputStream(); byte[] buffer=new byte[8192]; int count;
        while ((count=input.read(buffer))!=-1) {
            if (output.size()+count>IntelligenceManifestV2Verifier.MAX_ENVELOPE_BYTES) throw new IOException("Intelligence response exceeds limit");
            output.write(buffer,0,count);
        }
        return output.toByteArray();
    }
}
