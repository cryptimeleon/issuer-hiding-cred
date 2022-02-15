package org.cryptimeleon.issuerhiding;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15Signature;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15SigningKey;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;


public class Benchmark {
    long timerStart = -1;
    int testIterations = 100;
    int numberIssuers = 10;
    int attributeVectorLength = 10;
    BilinearGroup bilinearGroup;

    protected void measureTime(String str) {
        if (timerStart == -1) {
            timerStart = System.nanoTime();
        } else {
            long end = System.nanoTime();
            System.out.println(str + ": " + ((double) ((end - timerStart)/testIterations) / 1000000) + "ms averaged over "+testIterations+" iterations");
            timerStart = -1;
        }
    }

    public Benchmark() {
        this(new MclBilinearGroup(MclBilinearGroup.GroupChoice.BN254), 10, 10, 100);
    }

    public Benchmark(BilinearGroup bilinearGroup, int numberIssuers, int attributeVectorLength, int testIterations) {
        this.bilinearGroup = bilinearGroup;
        this.testIterations = testIterations;
        this.numberIssuers = numberIssuers;
        this.attributeVectorLength = attributeVectorLength;
    }

    public static void main(String[] args) {
        BilinearGroup bilinearGroup = new MclBilinearGroup(MclBilinearGroup.GroupChoice.BN254);
        Benchmark benchmark;
        if (args.length == 0)
            benchmark = new Benchmark();
        else if (args.length == 3)
            benchmark = new Benchmark(bilinearGroup, Integer.parseInt(args[0]), Integer.parseInt(args[1]), Integer.parseInt(args[2]));
        else
            throw new IllegalArgumentException("Pass either zero or three arguments. Format: numberIssuers numberAttributes iterations");

        benchmark.timeExecutions();
        benchmark.countGroupOps();
    }

    public void timeExecutions() {
        System.out.println("Timing "+numberIssuers+" issuers with "+attributeVectorLength+" attributes in "+bilinearGroup.toString()+".");

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
        system.verifyCred(system.restoreCredential(credRepr), attributes, issuerKeys.get(0).getVerificationKey());

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
            system.verifyPolicy(system.restorePolicy(policyRepr), issuerKeys.map(SignatureKeyPair::getVerificationKey));
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
            proofSystem.checkProof(commonInput, proofSystem.restoreProof(commonInput, proofRepr));
        }
        measureTime("Verify");
    }

    public void countGroupOps() {
        DebugBilinearGroup bilinearGroup = new DebugBilinearGroup(this.bilinearGroup.size(), BilinearGroup.Type.TYPE_3);

        System.out.println("Counting "+numberIssuers+" issuers with "+attributeVectorLength+" attributes in "+bilinearGroup.toString()+".");

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
        system.verifyCred(system.restoreCredential(credRepr), attributes, issuerKeys.get(0).getVerificationKey());

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
        proofSystem.checkProof(commonInput, proofSystem.restoreProof(commonInput, proofRepr));

        System.out.println(bilinearGroup.formatCounterDataAllBuckets(false));
    }
}
