package net.jsign.pe;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Created by vetsch on 4/24/16.
 */
public class PEInputLocalFile implements PEInput {

    private final File file;
    private  ExtendedRandomAccessFile raf;

    public PEInputLocalFile(File file) {
        this.file = file;
        try {
            this.raf = new ExtendedRandomAccessFile(file, "rw");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public int read(byte[] buffer) throws IOException {
        return raf.read(buffer);
    }

    public int read(byte[] buffer, int offset, int length) throws IOException {
        return raf.read(buffer, offset, length);
    }

    public int read() throws IOException {
        return raf.read();
    }

    public void seek(long offset) throws IOException {
        raf.seek(offset);
    }

    public long readDWord() throws IOException {
        return raf.readDWord();
    }

    public int readWord() throws IOException {
        return raf.readWord();
    }

    public long readQWord() throws IOException {
        return raf.readQWord();
    }

    public void close() throws IOException {
        raf.close();
    }

    public void write(byte[] data) throws IOException {
        raf.write(data);
    }

    public void writeByte(int data) throws IOException {
        raf.writeByte(data);
    }

    public long length()  {
        return file.length();
    }

    public String getName() {
        return file.getName();
    }

    public long lastModified() {
        return file.lastModified();
    }
}
