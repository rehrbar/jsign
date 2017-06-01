package net.jsign;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import sun.misc.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by vetsch on 4/29/16.
 */
public class CatalogFile {
    private List<SignedHashInfo> hashInfos;
    private X509CertificateHolder cert;

    private CMSSignedData signedData;
    private Store certStore;

    public CatalogFile(String fileName) throws IOException, CMSException {
        byte[] content = getContentFromFile(fileName);
        understandContent(content);
    }

    private byte[] getContentFromFile(String fileName) throws IOException {
        File in = new File(fileName);

        return IOUtils.readFully(new FileInputStream(in), -1, true);
    }

    public CatalogFile(byte[] fileContent) throws IOException, CMSException {
        understandContent(fileContent);
    }

    private void understandContent(byte[] fileContent) throws IOException, CMSException {
        signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(fileContent));

        extractCertificate(fileContent);
        if (isCertifictateTrusted(getCert())) {
            extractSignedHashes((DERSequence) signedData.toASN1Structure().getContent());
        }
    }

    private boolean isCertifictateTrusted(X509CertificateHolder cert) {
        return true;
    }

    private void extractCertificate(byte[] fileContent) throws CMSException {
        certStore = signedData.getCertificates();
        SignerId signerId = signedData.getSignerInfos().getSigners().iterator().next().getSID();
        cert = (X509CertificateHolder) certStore.getMatches(signerId).iterator().next();
    }

    private void extractSignedHashes(DERSequence input) {
        ASN1Primitive x = null;
        try {
            ASN1Encodable signedContent = ASN1Sequence.getInstance(input).getObjectAt(2);
            ASN1Encodable signedContentObject = getIndexFromSequence(signedContent, 1);
            ASN1Encodable y = getSequenceElementFromTaggedObject(signedContentObject, 4);
            hashInfos = getAllSignedHashes(y);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static List<SignedHashInfo> getAllSignedHashes(ASN1Encodable y) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(y);
        List<SignedHashInfo> result = new LinkedList<SignedHashInfo>();
        for (int i = 0; i < seq.size(); i++) {
            result.add(new SignedHashInfo(seq.getObjectAt(i)));
        }
        return result;
    }

    static ASN1Encodable getSequenceElementFromTaggedObject(ASN1Encodable encodableTaggedObject, int index) throws IOException {
        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(encodableTaggedObject);
        ASN1Encodable ss = taggedObject.getObjectParser(1, true);
        return getIndexFromSequence(ss, index);
    }

    static ASN1Encodable getIndexFromSequence(ASN1Encodable e, int index) {
        return ASN1Sequence.getInstance(e).getObjectAt(index);
    }

    public List<SignedHashInfo> getHashInfos() {
        return hashInfos;
    }

    public X509CertificateHolder getCert() {
        return cert;
    }

    public Collection<X509CertificateHolder> getCerts() throws CMSException {
        Collection<X509CertificateHolder> certs = new ArrayList<>();
        // TODO remove duplicated code
        signedData.getCertificates().getMatches(new Selector() {
            @Override
            public boolean match(Object o) {
                if(!(o instanceof X509CertificateHolder)) {
                    return false;
                }
                return true;
            }

            @Override
            public Object clone() {
                return null;
            }
        }).forEach(o -> {certs.add((X509CertificateHolder)o);});
        return certs;
    }
}


