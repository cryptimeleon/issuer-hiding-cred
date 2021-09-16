import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15Signature;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15SigningKey;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15VerificationKey;
import org.cryptimeleon.issuerhiding.CredentialShowNoninteractive;
import org.cryptimeleon.issuerhiding.CredentialShowProtocol;
import org.cryptimeleon.issuerhiding.CredentialSystem;
import org.cryptimeleon.issuerhiding.ValidIssuerPolicy;
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
    @Test
    public void test() {
        //BilinearGroup bilinearGroup = new BarretoNaehrigBilinearGroup(128);
        //BilinearGroup bilinearGroup = new DebugBilinearGroup(BilinearGroup.Type.TYPE_3);
        BilinearGroup bilinearGroup = new MclBilinearGroup();
        int attributeVectorLength = 5;
        CredentialSystem system = CredentialSystem.parGen(bilinearGroup, attributeVectorLength);

        //Issuer setup
        int numberIssuers = 7;
        Vector<SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey>> issuerKeys = Vector.generatePlain(system::issuerKeyGen, numberIssuers);

        //Credential issue
        RingElementVector attributes = bilinearGroup.getZn().getUniformlyRandomElements(attributeVectorLength);
        SPSGroth15Signature credential = system.issueCredential(issuerKeys.get(0).getSigningKey(), attributes);

        //Credential verify
        assertTrue(system.verifyCred(credential, attributes, issuerKeys.get(0).getVerificationKey()));

        //Policy creation
        ValidIssuerPolicy policy = system.genPolicy(issuerKeys.map(SignatureKeyPair::getVerificationKey));

        //Policy check
        system.verifyPolicy(policy, issuerKeys.map(SignatureKeyPair::getVerificationKey));

        //Create proof
        CredentialShowNoninteractive proofSystem = new CredentialShowNoninteractive(system);
        FiatShamirProof proof = proofSystem.createProof(new CredentialShowProtocol.CredentialShowCommonInput(policy),
                new CredentialShowProtocol.CredentialShowSecretInput(credential, attributes, issuerKeys.get(0).getVerificationKey(), policy.issuerCertificates.get(0)));

        //Verify proof
        proofSystem = new CredentialShowNoninteractive(system);
        assertTrue(proofSystem.checkProof(new CredentialShowProtocol.CredentialShowCommonInput(policy), proof));
    }
}
