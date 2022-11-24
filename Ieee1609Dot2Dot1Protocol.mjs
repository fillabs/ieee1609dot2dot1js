/**
 * @module Ieee1609Dot2Dot1Protocol
 */
import {Uint8, Uint16, Choice, Sequence, OctetString, SequenceOf } from 'asnjs';
import {HashAlgorithm, Ieee1609Dot2Data, Psid, Signature, SignerIdentifier} from 'Ieee1609Dot2js';
import {EeRaInterfacePdu}  from './Ieee1609Dot2Dot1EeRaInterface.mjs'
import {AcaEeInterfacePdu} from './Ieee1609Dot2Dot1AcaEeInterface.mjs'
import {AcaLaInterfacePdu} from './Ieee1609Dot2Dot1AcaLaInterface.mjs'
import {AcaMaInterfacePdu} from './Ieee1609Dot2Dot1AcaMaInterface.mjs'
import {AcaRaInterfacePdu} from './Ieee1609Dot2Dot1AcaRaInterface.mjs'
import {AcpcTreeId}        from './Ieee1609Dot2Dot1Acpc.mjs'
import {CertManagementPdu} from './Ieee1609Dot2Dot1CertManagement.mjs'
import {EcaEeInterfacePdu} from './Ieee1609Dot2Dot1EcaEeInterface.mjs'
import {EeMaInterfacePdu}  from './Ieee1609Dot2Dot1EeMaInterface.mjs'
import {EeRaInterfacePdu}  from './Ieee1609Dot2Dot1EeRaInterface.mjs'
import {LaMaInterfacePdu}  from './Ieee1609Dot2Dot1LaMaInterface.mjs'
import {LaRaInterfacePdu}  from './Ieee1609Dot2Dot1LaRaInterface.mjs'
import {MaRaInterfacePdu}  from './Ieee1609Dot2Dot1MaRaInterface.mjs'
   
import {Ieee1609Dot2Data_Unsecured, Ieee1609Dot2Data_Signed,
        Ieee1609Dot2Data_Encrypted, Ieee1609Dot2Data_SignedEncrypted, Ieee1609Dot2Data_EncryptedSigned,
        Ieee1609Dot2Data_SignedCertRequest }from './Ieee1609Dot2Extension.mjs'

/** @type {number} */
export const SecurityMgmtPsid = 35;
/** @type {number} */
export const BaseMbrPsid = 38;
export class AnyMbrPsid extends Psid {};

/**
 * @property {AcaEeInterfacePdu} aca_ee contains the interface structures defined for interaction
 * between the ACA and the EE.
 *
 * @property {AcaLaInterfacePdu} aca_la contains the interface structures defined for interaction
 * between the ACA and the LA.
 *
 * @property {AcaMaInterfacePdu} aca_ma contains the interface structures defined for interaction
 * between the ACA and the MA.
 *
 * @property {AcaRaInterfacePdu} aca_ra contains the interface structures defined for interaction
 * between the ACA and the RA.
 *
 * @property {CertManagementPdu} cert contains the interface structures defined for certificate
 * management.
 *
 * @property {EcaEeInterfacePdu} eca_ee contains the interface structures defined for interaction
 * between the ECA and the EE.
 *
 * @property {EeMaInterfacePdu} ee_ma contains the interface structures defined for interaction
 * between the EE and the MA.
 *
 * @property {EeRaInterfacePdu} ee_ra contains the interface structures defined for interaction
 * between the EE and the RA.
 *
 * @property {LaMaInterfacePdu} la_ma contains the interface structures defined for interaction
 * between the LA and the MA.
 *
 * @property {LaRaInterfacePdu} la_ra contains the interface structures defined for interaction
 * between the LA and the RA.
 *
 * @property {MaRaInterfacePdu} ma_ra contains the interface structures defined for interactions
 * between the MA and the RA.
 */
 export class ScmsPduContent extends Choice([
    { name: "aca_ee", type: AcaEeInterfacePdu},
    { name: "aca_la", type:  AcaLaInterfacePdu},
    { name: "aca_ma", type:  AcaMaInterfacePdu},
    { name: "aca_ra", type:  AcaRaInterfacePdu},
    { name: "cert",   type: CertManagementPdu},
    { name: "eca_ee", type: EcaEeInterfacePdu},
    { name: "ee_ma",  type: EeMaInterfacePdu},
    { name: "ee_ra",  type: EeRaInterfacePdu},
    { name: "la_ma",  type: LaMaInterfacePdu},
    { name: "la_ra",  type: LaRaInterfacePdu},
    { name: "ma_ra",  type: MaRaInterfacePdu},
    { extension :true }
]){}

/**
 * @class ScmsPdu
 *
 * @brief This is the parent structure that encompasses all parent structures
 * of interfaces defined in the SCMS. An overview of this structure is as
 * follows:
 *
 * @property {number} version contains the current version of the structure.
 * @property {ScmsPduContent} content
 *
 */
export class ScmsPdu extends Sequence([
    { name: "version", type: Uint8},
    { name: "content", type: ScmsPduContent
    }
]){}

export class ScmsPdu_Scoped extends ScmsPdu {}

export class X509Certificate extends OctetString() {}

export class X509SignerIdentifier extends Choice([
    { name: "certificate", type: SequenceOf(X509Certificate)},
    {extension: true}
]) {}

export class SignerSingleCert extends SignerIdentifier {}
export class SignerSelf extends SignerIdentifier {}

class ScmsPdu_RaAcaCertRequest extends ScmsPdu_Scoped {}
class ScmsPdu_EeEcaCertRequest extends ScmsPdu_Scoped {}
class ScmsPdu_EeRaCertRequest extends ScmsPdu_Scoped {}
class ScmsPdu_EeRaSuccessorEnrollmentCertRequest extends ScmsPdu_Scoped {}
class ScopedCertificateRequest extends ScmsPdu {}

class SignedCertificateRequest extends Sequence([
    { name: "hashAlgorithmId", type:  HashAlgorithm},
    { name: "tbsRequest", type: ScopedCertificateRequest},
    { name: "signer", type: SignerIdentifier},
    { name: "signature", type: Signature}
]){}

class SignedX509CertificateRequest extends Sequence ([
    { name: "hashAlgorithmId", type:  HashAlgorithm,},
    { name: "tbsRequest", type: ScopedCertificateRequest},
    { name: "signer", type: X509SignerIdentifier},
    { name: "signature", type: Signature
    }
]){}

export class AcaEeCertResponsePlainSpdu extends Ieee1609Dot2Data_Unsecured( ScmsPdu_Scoped ){}
export class AcaEeCertResponsePrivateSpdu extends Ieee1609Dot2Data_EncryptedSigned( ScmsPdu_Scoped ){}
export class AcaEeCertResponseCubkSpdu extends Ieee1609Dot2Data_Encrypted( ScmsPdu_Scoped ){}
export class RaAcaCertRequestSpdu extends Ieee1609Dot2Data_SignedCertRequest ( ScmsPdu_Scoped ) {}
export class AcaRaCertResponseSpdu extends Ieee1609Dot2Data_Signed( ScmsPdu_Scoped ) {}
export class CompositeCrlSpdu extends Ieee1609Dot2Data_Unsecured( ScmsPdu_Scoped ){}
export class CertificateChainSpdu extends Ieee1609Dot2Data_Unsecured( ScmsPdu_Scoped ){}
export class MultiSignedCtlSpdu extends Ieee1609Dot2Data_Unsecured( ScmsPdu_Scoped ){}
export class CtlSignatureSpdu extends Ieee1609Dot2Data_Signed( ScmsPdu_Scoped ) {}
export class CertificateManagementInformationStatusSpdu extends Ieee1609Dot2Data_Signed( ScmsPdu_Scoped ) {}
export class EeEcaCertRequestSpdu extends Ieee1609Dot2Data_SignedCertRequest ( ScmsPdu_Scoped ) {}
export class EeRaCertRequestSpdu extends Ieee1609Dot2Data {}
export class EeRa1609Dot2AuthenticatedCertRequestSpdu extends Ieee1609Dot2Data_SignedEncryptedCertRequest ( ScmsPdu_Scoped ){}
export class EeRaX509AuthenticatedCertRequestSpdu extends Ieee1609Dot2Data_Encrypted (ScmsPdu_Scoped ){}
export class RaEeCertAckSpdu extends Ieee1609Dot2Data_Signed (ScmsPdu_Scoped ){}
export class RaEeCertInfoSpdu extends Ieee1609Dot2Data_Unsecured (ScmsPdu_Scoped){}
export class RaEeCertAndAcpcInfoSpdu extends Ieee1609Dot2Data_Signed (ScmsPdu_Scoped){}
export class EeRaDownloadRequestPlainSpdu extends Ieee1609Dot2Data_Unsecured (ScmsPdu_Scoped){}
export class EeRaDownloadRequestSpdu extends Ieee1609Dot2Data_SignedEncrypted (ScmsPdu_Scoped) {}
export class EeRaSuccessorEnrollmentCertRequestSpdu extends Ieee1609Dot2Data_SignedEncryptedCertRequest (ScmsPdu_Scoped) {}
export class RaEeEnrollmentCertAckSpdu extends Ieee1609Dot2Data_Signed (ScmsPdu_Scoped) {}
export class EeRaEncryptedSignedMisbehaviorReportSpdu extends Ieee1609Dot2Data_EncryptedSigned (ScmsPdu_Scoped) {}
export class EeRaEncryptedMisbehaviorReportSpdu extends Ieee1609Dot2Data {}

class BaseSsp extends Sequence ([
    { name:"version", type: Uint8},
    {extension:true}
  ]){}

  class ElectorSsp extends BaseSsp {}
  class RootCaSsp extends BaseSsp {}
  class PgSsp extends BaseSsp {}
  class IcaSsp extends BaseSsp {}
  class EcaSsp extends BaseSsp {}
  class AcaSsp extends BaseSsp {}
  class CrlSignerSsp extends BaseSsp {}
  class DcmSsp extends BaseSsp {}

  class LaSsp extends Sequence([
    { name:"version", type: Uint8},
    { name:"laId", type: Uint16},
    {extension:true}
  ]){}

  class LopSsp extends BaseSsp {}

  class MaSsp extends Sequence([
    { name:"version", type: Uint8},
    { name:"relevantPsids", type: SequenceOf(Psid)},
    {extension:true}
  ]){}

  class RaSsp extends BaseSsp {}
  class EeSsp extends BaseSsp {}

  class AcpcSsp extends Choice([
    { name:"cam", type: SequenceOf(AcpcTreeId)},
    {extension:true}
  ]){}
  
  class DcSsp extends BaseSsp {}

export class ScmsSsp extends Choice([
    { name: "elector", type: ElectorSsp},
    { name: "root", type: RootCaSsp},
    { name: "pg", type: PgSsp},
    { name: "ica", type: IcaSsp},
    { name: "eca", type: EcaSsp},
    { name: "aca", type: AcaSsp},
    { name: "crl", type: CrlSignerSsp},
    { name: "dcm", type: DcmSsp},
    { name: "la", type: LaSsp},
    { name: "lop", type: LopSsp},
    { name: "ma", type: MaSsp},
    { name: "ra", type: RaSsp},
    { name: "ee", type: EeSsp},
    {extension:true},
	{ name: "dc", type: DcSsp}
]){}

