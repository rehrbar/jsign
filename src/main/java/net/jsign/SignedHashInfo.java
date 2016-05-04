package net.jsign;


import org.bouncycastle.asn1.*;

import java.io.IOException;

/**
 * Created by vetsch on 4/29/16.
 */
public class SignedHashInfo {
    private byte[] hashbytes;
    private String filename;
    private String osAttr;
    private String anders;


    public String description;

    private static final String fileId = "1.3.6.1.4.1.311.12.2.1";
    private static final String hashId = "1.3.6.1.4.1.311.2.1.4";
    private static final String osAttrId = "1.3.6.1.4.1.311.12.2.1";
    private static final String andersId = "1.3.6.1.4.1.311.12.2.2";

    public SignedHashInfo(ASN1Encodable asn1Object) throws IOException {
        ASN1Encodable a1 = getIndexFromSequence(asn1Object, 1);
        ASN1Set a2 = ASN1Set.getInstance(a1);

        for (ASN1Encodable a3 : a2) {
            ASN1Sequence s = ASN1Sequence.getInstance(a3);
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(s.getObjectAt(0));
            String ids = id.getId();

            ASN1Encodable d = s.getObjectAt(1);

            if (ids.equals(fileId)) {
                setAdditionalAttributes(d);
            } else if (ids.equals(hashId)) {
                ASN1Encodable x = ASN1Sequence.getInstance(ASN1Set.getInstance(d).getObjectAt(0)).getObjectAt(1);
                ASN1Encodable karl = ASN1Sequence.getInstance(x).getObjectAt(1);
                hashbytes = DEROctetString.getInstance(karl).getOctets();
            } else if (ids.equals(osAttrId)) {
                osAttr = d.toString();
            } else if (ids.equals(andersId)) {
                anders = d.toString();
            } else {
                System.err.println("Unknown Field Type");
            }

        }
    }

    private void setAdditionalAttributes(ASN1Encodable d) {
        ASN1Sequence infoSeq = ASN1Sequence.getInstance(ASN1Set.getInstance(d).getObjectAt(0));
        String fieldName = infoSeq.getObjectAt(0).toString();
        String fieldValue = new String(DEROctetString.getInstance(infoSeq.getObjectAt(2)).getOctets());
        if (fieldName.equals("File")) {
            filename =fieldValue;
        } else if (fieldName.equals("OSAttr")) {
            osAttr = fieldValue;
        } else {
            System.out.println("Unknown Attribute: " + fieldName);
        }
    }

    static ASN1Encodable getIndexFromSequence(ASN1Encodable e, int index) {
        return ASN1Sequence.getInstance(e).getObjectAt(index);
    }

    public static String byteArrayToHex(byte[] a) {
        if(a == null) {
            return "empty";
        }
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }


    public String getFilename() {
        return filename;
    }

    public byte[] getHashbytes() {
        return hashbytes;
    }


    public String getAnders() {
        return anders;
    }

}
