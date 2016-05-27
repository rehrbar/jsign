package net.jsign;

import org.bouncycastle.cms.CMSException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Created by vetsch on 4/29/16.
 */
public class CatalogTest {

    private static long fileC = 0;
    private static long hashC = 0;

    public static void main(String[] args) throws IOException, CMSException {
        String name = "";

        File d = new File("/home/vetsch/disk/h/catFiels");

        File out = new File("/home/vetsch/disk/h/allcatHashes");
        OutputStream outS = new FileOutputStream(out);

        for (File c : d.listFiles()) {
            fileC++;
            try {
                processFile(c.getAbsolutePath(), outS);
            } catch (NullPointerException e) {
            }

        }
        outS.close();
        System.out.println(fileC);
        System.out.println(hashC);
    }

    private static void processFile(String name, OutputStream out) throws IOException, CMSException {
        CatalogFile x = new CatalogFile(name);

        String publisherName = x.getCert().getSubject().toString();

        for (SignedHashInfo y : x.getHashInfos()) {
            if (y.getHashbytes() != null) {
                out.write(SignedHashInfo.byteArrayToHex(y.getHashbytes()).getBytes());
                out.write('\t');
                out.write(publisherName.getBytes());
                out.write('\n');
                hashC++;
            }

        }
    }
}
