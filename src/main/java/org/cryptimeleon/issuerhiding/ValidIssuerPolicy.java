package org.cryptimeleon.issuerhiding;

import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15Signature;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15SignatureScheme;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15VerificationKey;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;

public class ValidIssuerPolicy implements Representable {
    public SPSGroth15VerificationKey U;
    public Vector<SPSGroth15VerificationKey> validIssuers;
    public Vector<SPSGroth15Signature> issuerCertificates;

    public ValidIssuerPolicy(SPSGroth15VerificationKey u, Vector<SPSGroth15VerificationKey> validIssuers, Vector<SPSGroth15Signature> issuerCertificates) {
        U = u;
        this.validIssuers = validIssuers;
        this.issuerCertificates = issuerCertificates;
    }

    public ValidIssuerPolicy(Representation repr, SPSGroth15SignatureScheme groth1, SPSGroth15SignatureScheme groth2) {
        this.U = groth2.restoreVerificationKey(repr.obj().get("U"));
        this.validIssuers = new Vector<Representation>(repr.obj().get("validIssuers").list().getArray()).map(groth1::restoreVerificationKey);
        this.issuerCertificates = new Vector<Representation>(repr.obj().get("issuerCertificates").list().getArray()).map(groth2::restoreSignature);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("U", U.getRepresentation());
        repr.put("validIssuers", new ListRepresentation(validIssuers.map(Representable::getRepresentation)));
        repr.put("issuerCertificates", new ListRepresentation(issuerCertificates.map(Representable::getRepresentation)));
        return repr;
    }
}
