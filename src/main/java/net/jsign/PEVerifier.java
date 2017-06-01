package net.jsign;

import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.PEFile;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by vetsch on 4/24/16.
 */
public class PEVerifier {

    private final PEFile peFile;

    public PEVerifier(PEFile pefile) {
        this.peFile = pefile;
    }

    public PEVerifier(File file) throws IOException {
        this(new PEFile(file));
    }

    public PEVerifier(String fileName) throws IOException {
        this(new File(fileName));
    }

    public List<X509CertificateHolder> getCertificateChain() {
        List<X509CertificateHolder> result = new LinkedList<X509CertificateHolder>();
        try {
            X509CertificateHolder signer = getSignerCertificate(peFile, getSignedData(peFile));
            result.add(signer);
            // TODO add the rest of the chain

        } catch (CMSException e) {
            return result;
        }
        return result;


    }

    public boolean isCorrectlySigned() {
        try {
            return verifyAuthenticode(peFile);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifyAuthenticode(PEFile file) throws CMSException, IOException {
        CMSSignedData signedData = getSignedData(file);

        if (!isFileDigestCorrect(file, signedData)) {
            return false;
        }

        if (!wasSignedBySigner(getSignerCertificate(file, signedData), signedData)) {
            return false;
        }

        if (!isSignatureSignedByTrustedCA(file, signedData)) {
            return false;
        }

        return true;
    }

    private CMSSignedData getSignedData(PEFile file) throws CMSException {
        if(file.getCertificateTable().size() == 0) {
            throw new CMSException("No Certificate Table Entry");
        }
        CertificateTableEntry certificateTableEntry = file.getCertificateTable().get(0);
        return certificateTableEntry.getSignature();
    }

    private static boolean wasSignedBySigner(final X509CertificateHolder signerCertificate, CMSSignedData signedData) {
        // TODO check
        return true;
    }

    private static boolean isSignatureSignedByTrustedCA(PEFile file, CMSSignedData signedData) throws CMSException {
        // TODO check
        return true;
    }

    private static X509CertificateHolder getSignerCertificate(PEFile file, CMSSignedData signedData) throws CMSException {
        Store certStore = getCertificates(file);
        SignerId signerInfo = signedData.getSignerInfos().getSigners().iterator().next().getSID();

        return (X509CertificateHolder) certStore.getMatches(signerInfo).iterator().next();
    }

    private static Store getCertificates(PEFile file) throws CMSException {
        return file.getCertificateTable().get(0).getSignature().getCertificates();
    }


    private static boolean isFileDigestCorrect(PEFile file, CMSSignedData signedData) throws IOException {
        byte[] signedDigest = extractDigestFromSignature(signedData);

        AlgorithmIdentifier f = signedData.getDigestAlgorithmIDs().iterator().next();
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(f.getAlgorithm());

        byte[] computedDigest = file.computeDigest(digestAlgorithm);
        return Arrays.areEqual(computedDigest, signedDigest);
    }

    private static byte[] extractDigestFromSignature(CMSSignedData signedData) {
        ASN1Encodable contentInfo = signedData.toASN1Structure().getContent();
        ASN1Sequence spcIndirectDataContent = ASN1Sequence.getInstance(contentInfo);
        ASN1Encodable messageDigestP = spcIndirectDataContent.getObjectAt(2);
        ASN1Encodable messageDigest = ASN1Sequence.getInstance(messageDigestP).getObjectAt(1);
        ASN1TaggedObject digestInfo = ASN1TaggedObject.getInstance(messageDigest);
        ASN1Encodable digestInfoSeq = null;
        try {
            digestInfoSeq = digestInfo.getObjectParser(1, true);
        } catch (IOException e) {
            return new byte[0];
        }
        ASN1Encodable digestKarl = ASN1Sequence.getInstance(digestInfoSeq).getObjectAt(1);
        ASN1Encodable digestValue = ASN1Sequence.getInstance(digestKarl).getObjectAt(1);
        ASN1OctetString digestValueString = ASN1OctetString.getInstance(digestValue);
        return digestValueString.getOctets();
    }
    
    public X509CertificateHolder getCert() {
        try {
            return getSignerCertificate(peFile, getSignedData(peFile));
        } catch (CMSException e) {
            return null;
        }   
    }


    public Collection<X509CertificateHolder> getCerts() throws CMSException {
        Collection<X509CertificateHolder> certs = new ArrayList<>();
        // TODO remove duplicated code
        getSignedData(peFile).getCertificates().getMatches(new Selector() {
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
