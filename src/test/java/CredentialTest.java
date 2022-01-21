import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15Signature;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15SigningKey;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15VerificationKey;
import org.cryptimeleon.issuerhiding.CredentialShowNoninteractive;
import org.cryptimeleon.issuerhiding.CredentialShowProtocol;
import org.cryptimeleon.issuerhiding.CredentialSystem;
import org.cryptimeleon.issuerhiding.ValidIssuerPolicy;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBasicBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class CredentialTest {
    static long timerStart = -1;
    static int testIterations = 1;
    static int numberIssuers = 10;
    static int attributeVectorLength = 10;

    protected static void measureTime(String str) {
        if (timerStart == -1) {
            timerStart = System.nanoTime();
        } else {
            long end = System.nanoTime();
            System.out.println(str + ": " + ((end - timerStart)/testIterations / 1000000000) + "s, " + (((end - timerStart)/testIterations % 1000000000) / 1000000) + "ms averaged over "+testIterations+" iterations");
            timerStart = -1;
        }
    }

    @Test
    public void testTimes() {
        //BilinearGroup bilinearGroup = new BarretoNaehrigBilinearGroup(128);
        //BilinearGroup bilinearGroup = new DebugBilinearGroup(BilinearGroup.Type.TYPE_3);
        BilinearGroup bilinearGroup = new MclBilinearGroup();

        CredentialSystem system = CredentialSystem.parGen(bilinearGroup, attributeVectorLength);

        //Issuer setup
        Vector<SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey>> issuerKeys = Vector.generatePlain(system::issuerKeyGen, numberIssuers);
        //"Send" over issuer pks
        Vector<Representation> issuerPksRepr = issuerKeys.map(k -> k.getVerificationKey().getRepresentation());

        //Credential issue
        RingElementVector attributes = bilinearGroup.getZn().getUniformlyRandomElements(attributeVectorLength);
        Representation credRepr = null;
        SPSGroth15Signature credential = null;
        measureTime(null);
        for (int i=0;i<testIterations;i++) {
            credential = system.issueCredential(issuerKeys.get(0).getSigningKey(), attributes); //use existing issuer sk (imagine that's probably loaded all the time)
            credRepr = credential.getRepresentation();
        }
        measureTime("Issue");

        //Credential verify
        assertTrue(system.verifyCred(system.restoreCredential(credRepr), attributes, issuerKeys.get(0).getVerificationKey()));

        //Policy creation
        Representation policyRepr = null;
        ValidIssuerPolicy policy = null;
        measureTime(null);
        for (int i=0;i<testIterations;i++) {
            policy = system.genPolicy(issuerKeys.map(SignatureKeyPair::getVerificationKey));
            policyRepr = policy.getRepresentation();
        }
        measureTime("PresPolicy ("+numberIssuers+" issuers)");

        //Policy check
        measureTime(null);
        for (int i=0;i<testIterations;i++) {
            assertTrue(system.verifyPolicy(system.restorePolicy(policyRepr), issuerKeys.map(SignatureKeyPair::getVerificationKey)));
        }
        measureTime("VfPolicy ("+numberIssuers+" issuers)");

        //Create proof
        FiatShamirProof proof = null;
        Representation proofRepr = null;
        measureTime(null);
        for (int i=0;i<testIterations;i++) {
            CredentialShowNoninteractive proofSystem = new CredentialShowNoninteractive(system);
            proof = proofSystem.createProof(new CredentialShowProtocol.CredentialShowCommonInput(policy),
                    new CredentialShowProtocol.CredentialShowSecretInput(credential, attributes, issuerKeys.get(0).getVerificationKey(), policy.issuerCertificates.get(0)));
            proofRepr = proof.getRepresentation();
        }
        measureTime("Present");

        //Deserialize and verify proof (use already cached policy)
        measureTime(null);
        for (int i=0;i<testIterations;i++) {
            CredentialShowNoninteractive proofSystem = new CredentialShowNoninteractive(system);
            CommonInput commonInput = new CredentialShowProtocol.CredentialShowCommonInput(policy);
            assertTrue(proofSystem.checkProof(commonInput, proofSystem.restoreProof(commonInput, proofRepr)));
        }
        measureTime("Verify");
    }

    @Test
    public void testCount() {
        MclBilinearGroup mcl = new MclBilinearGroup();
        DebugBilinearGroup bilinearGroup = new DebugBilinearGroup(mcl.size(), BilinearGroup.Type.TYPE_3);

        CredentialSystem system = CredentialSystem.parGen(bilinearGroup, attributeVectorLength);

        //Issuer setup
        Vector<SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey>> issuerKeys = Vector.generatePlain(system::issuerKeyGen, numberIssuers);
        //"Send" over issuer pks
        Vector<Representation> issuerPksRepr = issuerKeys.map(k -> k.getVerificationKey().getRepresentation());

        //Credential issue
        bilinearGroup.setBucket("Issue");
        RingElementVector attributes = bilinearGroup.getZn().getUniformlyRandomElements(attributeVectorLength);
        Representation credRepr = null;
        SPSGroth15Signature credential = null;
        credential = system.issueCredential(issuerKeys.get(0).getSigningKey(), attributes); //use existing issuer sk (imagine that's probably loaded all the time)
        credRepr = credential.getRepresentation();

        //Credential verify
        bilinearGroup.setBucket("credential verify");
        assertTrue(system.verifyCred(system.restoreCredential(credRepr), attributes, issuerKeys.get(0).getVerificationKey()));

        //Policy creation
        bilinearGroup.setBucket("PresPolicy ("+numberIssuers+" issuers)");
        Representation policyRepr = null;
        ValidIssuerPolicy policy = null;
        policy = system.genPolicy(issuerKeys.map(SignatureKeyPair::getVerificationKey));
        policyRepr = policy.getRepresentation();

        //Policy check
        bilinearGroup.setBucket("VfPolicy ("+numberIssuers+" issuers)");
        system.verifyPolicy(system.restorePolicy(policyRepr), issuerKeys.map(SignatureKeyPair::getVerificationKey));

        //Create proof
        bilinearGroup.setBucket("Present");
        FiatShamirProof proof = null;
        Representation proofRepr = null;
        CredentialShowNoninteractive proofSystem = new CredentialShowNoninteractive(system);
        proof = proofSystem.createProof(new CredentialShowProtocol.CredentialShowCommonInput(policy),
                new CredentialShowProtocol.CredentialShowSecretInput(credential, attributes, issuerKeys.get(0).getVerificationKey(), policy.issuerCertificates.get(0)));
        proofRepr = proof.getRepresentation();

        //Deserialize and verify proof (use already cached policy)
        bilinearGroup.setBucket("Verify");
        proofSystem = new CredentialShowNoninteractive(system);
        CommonInput commonInput = new CredentialShowProtocol.CredentialShowCommonInput(policy);
        assertTrue(proofSystem.checkProof(commonInput, proofSystem.restoreProof(commonInput, proofRepr)));

        System.out.println(bilinearGroup.formatCounterDataAllBuckets(false));
    }
}
