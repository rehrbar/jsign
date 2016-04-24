package net.jsign.pe;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;

import java.io.IOException;

/**
 * Created by vetsch on 4/24/16.
 */
public interface PEInput {

    int read(byte[] buffer) throws IOException;

    int read(byte[] buffer, int offset, int length) throws IOException;

    int read() throws IOException;

    void seek(long offset) throws IOException;

    long readDWord() throws IOException;

    int readWord() throws IOException;

    long readQWord() throws IOException;

    void close() throws IOException;

    void write(byte[] data) throws IOException;

    void writeByte(int data) throws IOException;

    long length();

    String getName();

    long lastModified();

}
