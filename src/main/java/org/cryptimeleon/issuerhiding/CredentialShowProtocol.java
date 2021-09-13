package org.cryptimeleon.issuerhiding;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendFirstValue;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15Signature;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15VerificationKey;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.expressions.exponent.ExponentExpr;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.ExponentExpressionVector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.util.function.Function;

public class CredentialShowProtocol extends SendThenDelegateProtocol {
    public final CredentialSystem system;
    public final BilinearGroup bilinearGroup;
    public final BilinearMap e;
    public final Zn zn;

    public CredentialShowProtocol(CredentialSystem system) {
        this.system = system;
        this.bilinearGroup = system.getBilinearGroup();
        this.e = bilinearGroup.getBilinearMap();
        this.zn = bilinearGroup.getZn();
    }

    @Override
    protected SendThenDelegateFragment.ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
        //Choose blinding values
        Zn.ZnElement alpha = zn.getUniformlyRandomNonzeroElement(),
                beta = zn.getUniformlyRandomNonzeroElement(),
                gamma = zn.getUniformlyRandomNonzeroElement(),
                delta = zn.getUniformlyRandomNonzeroElement();

        //Randomization factors for credential and policy signature
        Zn.ZnElement rCred = zn.getUniformlyRandomNonzeroElement();
        Zn.ZnElement rPol = zn.getUniformlyRandomNonzeroElement();

        //Blind credential
        GroupElement Rtilde = ((CredentialShowSecretInput) secretInput).credential.getGroupElementSigma1HatR().pow(rCred);
        GroupElement Sprime = ((CredentialShowSecretInput) secretInput).credential.getGroupElementSigma2S().pow(rCred.inv().mul(alpha.inv())).compute();
        GroupElement Tprime = ((CredentialShowSecretInput) secretInput).credential.getGroupElementSigma3Ti()[0].pow(rCred.inv().mul(beta.inv())).compute();

        //Blind issuer's public key
        GroupElement ipkjPrime = ((CredentialShowSecretInput) secretInput).issuerKey.getGroupElementV().pow(gamma.inv()).compute();

        //Blind signature on issuer's public key
        GroupElement Rj = ((CredentialShowSecretInput) secretInput).issuerCertificate.getGroupElementSigma1HatR().pow(rPol).compute();
        GroupElement SjTilde = ((CredentialShowSecretInput) secretInput).issuerCertificate.getGroupElementSigma2S().pow(rPol.inv()).compute();
        GroupElement TjTilde = ((CredentialShowSecretInput) secretInput).issuerCertificate.getGroupElementSigma3Ti()[0].pow(rPol.inv().mul(delta.inv())).compute();

        //Send blinded values
        builder.setSendFirstValue(new CredentialShowSendFirstValue(Rtilde, Sprime, Tprime, ipkjPrime, Rj, SjTilde, TjTilde));

        //Set up witnesses for proof
        builder.putWitnessValue("alpha", alpha);
        builder.putWitnessValue("beta", beta);
        builder.putWitnessValue("gamma", gamma);
        builder.putWitnessValue("delta", delta);
        ((CredentialShowSecretInput) secretInput).attributes.forEach((i, attr) -> builder.putWitnessValue("a_"+i, (Zn.ZnElement) attr));

        return builder.build();
    }

    @Override
    protected CredentialShowSendFirstValue restoreSendFirstValue(CommonInput commonInput, Representation repr) {
        return new CredentialShowSendFirstValue(bilinearGroup, repr);
    }

    @Override
    protected CredentialShowSendFirstValue simulateSendFirstValue(CommonInput commonInput) {
        Zn.ZnElement rPol = zn.getUniformlyRandomNonzeroElement();
        GroupElement Rj = ((CredentialShowCommonInput) commonInput).policy.issuerCertificates.get(0).getGroupElementSigma1HatR().pow(rPol).compute();
        GroupElement SjTilde = ((CredentialShowCommonInput) commonInput).policy.issuerCertificates.get(0).getGroupElementSigma2S().pow(rPol.inv());
        return new CredentialShowSendFirstValue(
                system.getBilinearGroup().getG2().getUniformlyRandomNonNeutral(),
                system.getBilinearGroup().getG1().getUniformlyRandomNonNeutral(),
                system.getBilinearGroup().getG1().getUniformlyRandomNonNeutral(),
                system.getBilinearGroup().getG2().getUniformlyRandomNonNeutral(),
                Rj,
                SjTilde,
                system.getBilinearGroup().getG2().getUniformlyRandomNonNeutral()
        );
    }

    @Override
    protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendFirstValue sendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
        SchnorrZnVariable alpha = builder.addZnVariable("alpha", zn);
        SchnorrZnVariable beta = builder.addZnVariable("beta", zn);
        SchnorrZnVariable gamma = builder.addZnVariable("gamma", zn);
        SchnorrZnVariable delta = builder.addZnVariable("delta", zn);

        ExponentExpressionVector attributeVector = getAttributeVector(varname -> builder.addZnVariable(varname, zn));

        CredentialShowCommonInput common = (CredentialShowCommonInput) commonInput;
        CredentialShowSendFirstValue sfv = (CredentialShowSendFirstValue) sendFirstValue;

        builder.addSubprotocol("groth1", new LinearStatementFragment(
                e.applyExpr(sfv.Sprime.pow(alpha), sfv.Rtilde)
                        .isEqualTo(e.applyExpr(system.getGroth1().getPp().getGroupElementsYi()[0], system.getGroth1().getPp().getOtherGroupGenerator()).op(
                                e.applyExpr(system.getGroth1().getPp().getPlaintextGroupGenerator().pow(gamma), sfv.ipkjPrime)
                        ))
        ));

        builder.addSubprotocol("groth1Message", new LinearStatementFragment(
                e.applyExpr(sfv.Tprime.pow(beta), sfv.Rtilde).isEqualTo(
                        e.applyExpr(system.getGroth1().getPp().getGroupElementsYi()[0].pow(gamma), sfv.ipkjPrime).op(
                                e.applyExpr(system.getPedersenHashBases().expr().innerProduct(attributeVector), system.getGroth1().getPp().getOtherGroupGenerator())
                        )
                )
        ));

        //Groth2 statement doesn't depend on variables and is checked in provideAdditionalCheck()

        builder.addSubprotocol("groth2Message", new LinearStatementFragment(
                e.applyExpr(sfv.Rj.pow(delta), sfv.TjTilde).isEqualTo(
                        e.applyExpr(common.policy.U.getGroupElementV(), system.getGroth2().getPp().getGroupElementsYi()[0]).op(
                                e.applyExpr(system.getGroth1().getPp().getOtherGroupGenerator().pow(gamma), sfv.ipkjPrime)
                        )
                )
        ));

        return builder.build();
    }

    @Override
    protected BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendFirstValue sendFirstValue) {
        CredentialShowSendFirstValue sendFirstValue1 = (CredentialShowSendFirstValue) sendFirstValue;
        CredentialShowCommonInput commonInput1 = (CredentialShowCommonInput) commonInput;
        return e.applyExpr(sendFirstValue1.Rj, sendFirstValue1.SjTilde).isEqualTo(
                e.applyExpr(system.getGroth2().getPp().getOtherGroupGenerator(), system.getGroth2().getPp().getGroupElementsYi()[0])
                        .op(e.applyExpr(commonInput1.policy.U.getGroupElementV(), system.getGroth2().getPp().getPlaintextGroupGenerator()))
        ); //TODO these values can be precomputed
    }

    @Override
    public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
        return new ZnChallengeSpace(zn);
    }

    public static class CredentialShowSecretInput implements SecretInput {
        public final SPSGroth15Signature credential;
        public final RingElementVector attributes;
        public final SPSGroth15VerificationKey issuerKey;
        public final SPSGroth15Signature issuerCertificate;

        public CredentialShowSecretInput(SPSGroth15Signature credential, RingElementVector attributes, SPSGroth15VerificationKey issuerKey, SPSGroth15Signature issuerCertificate) {
            this.credential = credential;
            this.attributes = attributes;
            this.issuerKey = issuerKey;
            this.issuerCertificate = issuerCertificate;
        }
    }

    protected ExponentExpressionVector getAttributeVector(Function<String, ExponentExpr> variableInstantiator) {
        return new ExponentExpressionVector(system.getPedersenHashBases().map((i, hi) -> variableInstantiator.apply("a_"+i))); //change to prove something else (like that the attributes are (1,2,3,a3+a1))
    }

    public static class CredentialShowCommonInput implements CommonInput {
        public final ValidIssuerPolicy policy;

        public CredentialShowCommonInput(ValidIssuerPolicy policy) {
            this.policy = policy;
        }
    }

    public static class CredentialShowSendFirstValue implements SendFirstValue {
        @UniqueByteRepresented
        @Represented(restorer = "G2")
        GroupElement Rtilde;

        @UniqueByteRepresented
        @Represented(restorer = "G1")
        GroupElement Sprime;

        @UniqueByteRepresented
        @Represented(restorer = "G1")
        GroupElement Tprime;

        @UniqueByteRepresented
        @Represented(restorer = "G2")
        GroupElement ipkjPrime;

        @UniqueByteRepresented
        @Represented(restorer = "G1")
        GroupElement Rj;

        @UniqueByteRepresented
        @Represented(restorer = "G2")
        GroupElement SjTilde;

        @UniqueByteRepresented
        @Represented(restorer = "G2")
        GroupElement TjTilde;

        public CredentialShowSendFirstValue(GroupElement rtilde, GroupElement sprime, GroupElement tprime, GroupElement ipkjPrime, GroupElement rj, GroupElement sjTilde, GroupElement tjTilde) {
            Rtilde = rtilde;
            Sprime = sprime;
            Tprime = tprime;
            this.ipkjPrime = ipkjPrime;
            Rj = rj;
            SjTilde = sjTilde;
            TjTilde = tjTilde;
        }

        public CredentialShowSendFirstValue(BilinearGroup group, Representation repr) {
            new ReprUtil(this).register(group).deserialize(repr);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
        }

        @Override
        public Representation getRepresentation() {
            return ReprUtil.serialize(this);
        }
    }
}
