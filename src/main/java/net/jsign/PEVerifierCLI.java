package net.jsign;

import org.bouncycastle.cert.X509CertificateHolder;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Created by vetsch on 4/24/16.
 */
public class PEVerifierCLI {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: PEVerifier <executable>");
            return;
        }

        File file = new File(args[0]);
        if (!file.exists()) {
            System.err.println("File does not exist");
            return;
        }

        PEVerifier verifier;
        try {
            verifier = new PEVerifier(file);
        } catch (IOException e) {
            System.err.println("Unable to verify file");
            return;
        }

        if (verifier.isCorrectlySigned()) {
            System.out.println("Signature:\tValid");
            printSignerInformation(verifier);
        } else {
            System.err.println("Signature:\tInvalid");
        }
    }

    private static void printSignerInformation(PEVerifier verifier) {
        List<X509CertificateHolder> certs = verifier.getCertificateChain();
        for(X509CertificateHolder cert : certs) {
            System.out.println(cert.getSubject().toString());
        }
    }
}
