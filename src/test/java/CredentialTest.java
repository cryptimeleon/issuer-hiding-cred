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
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class CredentialTest {
    static int numberIssuers = 5;
    static int attributeVectorLength = 3;

    @Test
    public void testRun() {
        BilinearGroup bilinearGroup = new DebugBilinearGroup(BilinearGroup.Type.TYPE_3);

        CredentialSystem system = CredentialSystem.parGen(bilinearGroup, attributeVectorLength);

        //Issuer setup
        Vector<SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey>> issuerKeys = Vector.generatePlain(system::issuerKeyGen, numberIssuers);
        //"Send" over issuer pks
        Vector<Representation> issuerPksRepr = issuerKeys.map(k -> k.getVerificationKey().getRepresentation());

        //Credential issue
        RingElementVector attributes = bilinearGroup.getZn().getUniformlyRandomElements(attributeVectorLength);
        SPSGroth15Signature credential = system.issueCredential(issuerKeys.get(0).getSigningKey(), attributes); //use existing issuer sk (imagine that's probably loaded all the time)
        Representation credRepr = credential.getRepresentation();

        //Credential verify
        assertTrue(system.verifyCred(system.restoreCredential(credRepr), attributes, issuerKeys.get(0).getVerificationKey()));

        //Policy creation
        ValidIssuerPolicy policy = system.genPolicy(issuerKeys.map(SignatureKeyPair::getVerificationKey));
        Representation policyRepr = policy.getRepresentation();

        //Policy check
        assertTrue(system.verifyPolicy(system.restorePolicy(policyRepr), issuerKeys.map(SignatureKeyPair::getVerificationKey)));

        //Create proof
        CredentialShowNoninteractive proofSystem = new CredentialShowNoninteractive(system);
        FiatShamirProof proof = proofSystem.createProof(new CredentialShowProtocol.CredentialShowCommonInput(policy),
                new CredentialShowProtocol.CredentialShowSecretInput(credential, attributes, issuerKeys.get(0).getVerificationKey(), policy.issuerCertificates.get(0)));
        Representation proofRepr = proof.getRepresentation();

        //Deserialize and verify proof (use already cached policy)
        CredentialShowNoninteractive proofSystemVerifier = new CredentialShowNoninteractive(system);
        CommonInput commonInput = new CredentialShowProtocol.CredentialShowCommonInput(policy);
        assertTrue(proofSystemVerifier.checkProof(commonInput, proofSystemVerifier.restoreProof(commonInput, proofRepr)));
    }
}
