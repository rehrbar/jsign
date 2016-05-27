package net.jsign;

import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.PEFile;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.Iterator;

/**
 * Created by vetsch on 4/21/16.
 */
public class Runn {
    public static void main(String[] args) {
        File a = new File("/tmp/putty.exe");
        File out = new File("/tmp/cert.der");

        try {
            PEFile p = new PEFile(a);

            if (verifyAuthenticode(p)) {
                p("VALID");
            } else {
                p("INVALID");
            }
        } catch (IOException e) {
            System.err.println("Unable to verify Certificate");
        }
        /*OutputStream outS = new FileOutputStream(out);

        p.printInfo(System.out);

        //   p(p.get)
        p(p.getAddressOfEntryPoint());
        p(p.getSizeOfCode());
        p(p.getSizeOfHeaders());
        p(p.getBaseOfCode());
        p(p.getSectionAlignment());
        byte[] e = new byte[1024000];

        //InputStream exe = new FileInputStream(a);
        //exe.read(e, 0x59000, exe.available() - 0x5900);
        //outS.write(e);


        CertificateTableEntry myCert = p.getCertificateTable().get(0);


        CMSSignedData signedData = myCert.getSignature();
        Set<AlgorithmIdentifier> dids = signedData.getDigestAlgorithmIDs();
        // dids.
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        final Store certs = signedData.getCertificates();

        SignerInformation m27 = signedData.getSignerInfos().getSigners().iterator().next();


        for (Object f : m27.getSignedAttributes().toHashtable().keySet()) {
            Attribute va = (Attribute) m27.getSignedAttributes().toHashtable().get(f);
            p(va.getAttrValues().toString());

        }

        byte[] allb = myCert.toBytes();
        byte[] sig = Arrays.copyOfRange(allb, allb.length - 256 - 4, allb.length - 4);
        p("signature");
        pa(sig);


        //  p(m27.getDigestAlgorithmID().toASN1Primitive().toString());
        byte[] digest = p.computeDigest(DigestAlgorithm.SHA1);
        p("computed digest");
        pa(digest);


        p("Extracted Digest");
        pa(extractDigestFromSignature(signedData));
        // signedData*/

    }//1.2.840.113549.1.9.4)

    private static boolean verifyAuthenticode(PEFile p) {
        return false;
    }


    private static void pa(byte[] bytes) {
        Boolean flag = false;
        for (byte b : bytes) {
            System.out.print(fillZeros(Integer.toHexString(b & 0XFF), 2));
            if (flag) {
                //System.out.append(' ');
            }
            flag = !flag;
        }
        System.out.print('\n');
    }

    private static String fillZeros(String in, int c) {
        while (in.length() < c) {
            in = '0' + in;
        }
        return in;
    }


    private static void p(Object o) {
        System.out.println(o);
    }


    private static void getAuthentiCode(byte[] data, byte[] signature, X509CertificateHolder certificate) throws NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException {

        Signature x = Signature.getInstance("RSAwithSHA1");
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificate);
        x.initVerify(cert);
        x.update(data);
        if (x.verify(signature)) {
            p("VALID");
        } else {
            p("INVALID");
        }
        /*
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);

        JcaSignerInfoVerifierBuilder contentVerifier = new JcaSignerInfoVerifierBuilder(digestCalculatorProvider);

       // SignerInformationVerifier contenVerifierI = contentVerifier.build(certificate);
        SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(shaSigner, certificate);

        ContentVerifierProvider contentVerifierI = new ContentVerifierProvider() {
            public boolean hasAssociatedCertificate() {
                return false;
            }

            public X509CertificateHolder getAssociatedCertificate() {
                return null;
            }

            public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier) throws OperatorCreationException {
                return null;
            }
    }


    SignerInformationVerifier x = new SignerInformationVerifier(null, new DefaultCMSSignatureEncryptionAlgorithmFinder(), contenVerifierI, digestCalculatorProvider);

    SignerInformationVerifier y = new SignerInformatioVerifierBuilder();
    //public SignerInformationVerifier(
    //
    //  CMSSignatureAlgorithmNameGenerator sigNameGenerator,
    //  SignatureAlgorithmIdentifierFinder sigAlgorithmFinder,
    //  ContentVerifierProvider verifierProvider,
    //  DigestCalculatorProvider digestProvider)


    byte[] signedContent = content.toASN1Primitive().getEncoded("DER");

    OutputStream out = signerInfoGenerator.getCalculatingOutputStream();
    out.write(signedContent,2,signedContent.length-2); // skip the first 2 bytes as specified
    out.flush();
    out.close();

    signerInfo=signerInfoGenerator.generate(contentTypeOID);

    byte[] calculatedDigest = signerInfoGenerator.getCalculatedDigest();
    return calculatedDigest;*/

    }
}
