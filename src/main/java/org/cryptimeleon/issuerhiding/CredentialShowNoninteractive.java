package org.cryptimeleon.issuerhiding;

import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;

public class CredentialShowNoninteractive extends FiatShamirProofSystem {
    public CredentialShowNoninteractive(CredentialSystem system) {
        super(new CredentialShowProtocol(system));
    }
}
