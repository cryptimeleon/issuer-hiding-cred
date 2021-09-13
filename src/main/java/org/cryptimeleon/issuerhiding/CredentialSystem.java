package org.cryptimeleon.issuerhiding;

import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.groth15.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;

import java.util.stream.IntStream;

public class CredentialSystem implements StandaloneRepresentable {
    @Represented
    private BilinearGroup bilinearGroup;
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElementVector pedersenHashBases;
    @Represented
    private SPSGroth15SignatureScheme groth1, groth2;

    public CredentialSystem(BilinearGroup bilinearGroup, GroupElementVector pedersenHashBases, SPSGroth15SignatureScheme groth1, SPSGroth15SignatureScheme groth2) {
        this.bilinearGroup = bilinearGroup;
        this.pedersenHashBases = pedersenHashBases;
        this.groth1 = groth1;
        this.groth2 = groth2;
    }

    public CredentialSystem(Representation repr) {
        ReprUtil.deserialize(this, repr);
    }

    public static CredentialSystem parGen(BilinearGroup bilinearGroup, int attributeVectorLength) {
        return new CredentialSystem(bilinearGroup, bilinearGroup.getG1().getUniformlyRandomElements(attributeVectorLength),
                new SPSGroth15SignatureScheme(new SPSGroth15PublicParametersGen().generatePublicParameter(bilinearGroup, SPSGroth15PublicParametersGen.Groth15Type.type1, 1)),
                new SPSGroth15SignatureScheme(new SPSGroth15PublicParametersGen().generatePublicParameter(bilinearGroup, SPSGroth15PublicParametersGen.Groth15Type.type2, 1))
        );
    }

    public SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey> issuerKeyGen() {
        return groth1.generateKeyPair(1);
    }

    public SPSGroth15Signature issueCredential(SPSGroth15SigningKey issuerKey, RingElementVector attributes) {
        return (SPSGroth15Signature) groth1.sign(issuerKey, pedersenHashBases.innerProduct(attributes));
    }

    public boolean verifyCred(SPSGroth15Signature cred, RingElementVector attributes, SPSGroth15VerificationKey ipk) {
        return groth1.verify(ipk, cred, pedersenHashBases.innerProduct(attributes));
    }

    public ValidIssuerPolicy genPolicy(Vector<SPSGroth15VerificationKey> validIssuers) {
        SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey> verifierKeys = groth2.generateKeyPair(1);
        Vector<SPSGroth15Signature> issuerCertificates = validIssuers.map(
                issuerKey -> (SPSGroth15Signature) groth2.sign(verifierKeys.getSigningKey(), issuerKey.getGroupElementV())
        );
        return new ValidIssuerPolicy(verifierKeys.getVerificationKey(), validIssuers, issuerCertificates);
    }

    public boolean verifyPolicy(ValidIssuerPolicy policy, Vector<SPSGroth15VerificationKey> validIssuers) {
        if (!policy.validIssuers.equals(validIssuers))
            return false;
        return IntStream.range(0, policy.validIssuers.length()).parallel()
                .allMatch(i -> groth2.verify(policy.U, policy.issuerCertificates.get(i), policy.validIssuers.get(i).getGroupElementV()));
    }

    public ValidIssuerPolicy restorePolicy(Representation repr) {
        return new ValidIssuerPolicy(repr, groth1, groth2);
    }

    public SPSGroth15VerificationKey restoreIssuerPublicKey(Representation repr) {
        return groth1.restoreVerificationKey(repr);
    }

    public SPSGroth15SigningKey restoreIssuerSecretKey(Representation repr) {
        return groth1.restoreSigningKey(repr);
    }

    public SPSGroth15Signature restoreCredential(Representation repr) {
        return groth1.restoreSignature(repr);
    }

    public BilinearGroup getBilinearGroup() {
        return bilinearGroup;
    }

    public GroupElementVector getPedersenHashBases() {
        return pedersenHashBases;
    }

    public SPSGroth15SignatureScheme getGroth1() {
        return groth1;
    }

    public SPSGroth15SignatureScheme getGroth2() {
        return groth2;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
