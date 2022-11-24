import { OctetString, OpenType, SequenceOf, Uint8, Sequence, Integer } from "asnjs"
import { HashedId8, Time32, Certificate, Psid } from "Ieee1609Dot2js"
import { CtlSignatureSpdu, MultiSignedCtlSpdu } from "./Ieee1609Dot2Dot1Protocol.mjs"
import { SecuredCrl } from "./Ieee1609Dot2Crl.mjs"

/**
 * @class HashedId48
 *
 * @brief This data structure contains the hash of another data structure,
 * calculated with a hash function with at least 48 bytes of output length.
 * The HashedId48 for a given data structure is calculated by calculating the
 * hash of the encoded data structure and taking the low-order 48 bytes of
 * the hash output if necessary. If the data structure is subject to
 * canonicalization it is canonicalized before hashing.
 */
 export class HashedId48 extends OctetString(48) {}
 export class HashedId32 extends OctetString(32) {}

/**
 * @class CompositeCrl
 *
 * @brief This structure is used to encapsulate CRLs and a CTL. An overview
 * of this structure is as follows:
 *
 * @property {SecuredCrl[]} crl contains a list of signed CRLs for different (CRACA ID, CRL
 * series) pairs. The CRLs are signed individually, and this document does not
 * specify the order in which they should appear.
 *
 * @property {MultiSignedCtlSpdu} homeCtl contains a CTL. If the composite CRL was requested via the
 * mechanisms given in 6.3.5.8, the ElectorGroupId in this CTL is the same as
 * the ElectorGroupId provided in the request. The intent is that this is the
 * "home" CTL of the requester, but this field can in practice be used to
 * provide any CTL with any ElectorGroupId value.
 */
 export class CompositeCrl extends Sequence([
  {name:"crl"      , type:SequenceOf(SecuredCrl)},
  {name:"homeCtl"  , type:MultiSignedCtlSpdu},
  {extension:true}
]){}

/**
 * @class CertificateChain
 *
 * @brief This structure is used to encapsulate certificates and a CTL. An
 * overview of this structure is as follows:
 *
 * @property {MultiSignedCtlSpdu} homeCtl contains a CTL. If the certificate chain was requested via
 * the mechanisms given in 6.3.5.7, the ElectorGroupId in this CTL is the
 * same as the ElectorGroupId provided in the request. The intent is that
 * this is the "home" CTL of the requester, but this field can in practice be
 * used to provide any CTL.
 *
 * @property {Certificate[]} others contains additional valid certificates of the CAs and the
 * MAs chosen by means outside the scope of this document.
 */
 export class CertificateChain extends Sequence([
  {name:"homeCtl" ,type:MultiSignedCtlSpdu},
  {name:"others"  ,type:SequenceOf(Certificate)},
  {extension:true}
]){}

/**
 * @class ElectorGroupId
 *
 * @brief This structure identifies a group of electors that sign a series of
 * CTLs for a specific purpose. Registration of ElectorGroupId values is
 * managed by the IEEE RA; see http://standards.ieee.org/regauth. A list of
 * assigned ElectorGroupId values is provided in K.1.
 */
 export class ElectorGroupId extends OctetString(8) {}

 /**
  * @class CtlSequenceNumber
  *
  * @brief This structure is used to encode the CTL sequence number. This
  * document does not specify semantics of this type once it reaches its
  * maximum value.
  */
 export class  CtlSequenceNumber extends UInt16 {}
 
 /**
  * @class CtlElectorEntry
  *
  * @brief This structure contains the hash of an elector certificate.
  */
 export class CtlElectorEntry extends HashedId48 {}
 
 /**
  * @class CtlRootCaEntry
  *
  * @brief This structure contains the hash of a root CA certificate.
  */
 export class CtlRootCaEntry extends HashedId32 {}
   
 /**
 * @class Ieee1609dot2dot1MsctlType
 *
 * @brief This is the integer used to identify the type of the CTL.
 */
 export class Ieee1609dot2dot1MsctlType extends Uint8 {}
 
 /** @type {Ieee1609dot2dot1MsctlType} */
 export const fullIeeeCtl = 1;

/**
 * @class FullIeeeTbsCtl
 *
 * @brief This structure specifies a CTL that contains information about the
 * complete set of certificates trusted by the electors that sign the CTL. An
 * overview of this structure is as follows:
 *
 * <br><br>NOTE 1: If in future CTL types are defined that contain the same
 * information as, or a subset of the information in, the fullIeeeCtl, those
 * types are anticipated to contain the same sequence number as the
 * corresponding fullIeeeCtl.
 *
 * <br><br>NOTE 2: Any root CA or elector certificate that is not on the CTL is
 * not trusted. The electorRemove and rootCaRemove are intended to be used
 * only if the SCMS manager wants to explicitly indicate that a previously
 * trusted entity (elector or root CA) is now not trusted even though that
 * entity's certificate is still within its validity period. In practice, it
 * is anticipated that the remove fields (electorRemove and rootCaRemove)
 * will almost always be sequences of length 0.
 *
 * @property {Ieee1609dot2dot1MsctlType} type contains the type of the CTL. It is identical to the type
 * field that appears in the enclosing MultiSignedCtl. The field is included
 * here as well to provide the simplest mechanism to help ensure that the
 * type is included in the calculated CTL hash.
 *
 * @property {ElectorGroupId} electorGroupId contains the group of electors that have signed the
 * CTL. It plays a role similar to CrlSeries in a CRL. This field is intended
 * to be globally unique in the universe of all systems that use the
 * MultiSignedCtl. See the specification of ElectorGroupId for discussion of
 * a convention that can be followed to enable uniqueness.
 *
 * @property {CtlSequenceNumber} sequenceNumber contains the sequence number of the CTL. This is
 * incremented by 1 every time a new FullIeeeTbsCtl is issued. 
 *
 * @property {Time32} effectiveDate contains the time when the CTL is to take effect.
 * This is to be greater than or equal to the effectiveDate field in the CTL
 * with the same electorGroupId and the previous sequence number.
 *
 * @property {CtlElectorEntry[]} electorApprove contains the list of hashes of the elector
 * certificates that are approved as of the effective date. The hash is
 * calculated with the same hash algorithm that is used to hash the elector
 * certificate for signing.
 *
 * @property {CtlElectorEntry[]} electorRemove contains the list of hashes of the elector
 * certificates that are valid (that is, not expired) on the effective date and
 * are not approved, as of the effective date, to sign a CTL. The hash is
 * calculated with the same hash algorithm that is used to hash the elector
 * certificate for signing. This field is to be considered informational as a
 * certificate that is not included in electorApprove is not valid even if it
 * does not appear in electorRemove.
 *
 * @property {CtlRootCaEntry[]} rootCaApprove contains the list of root CA certificates that are
 * approved as of the effective date. The hash is calculated with the same
 * hash algorithm that is used to hash the root certificate for signing. If
 * the root certificate is signed with a hash function with a 48 octet
 * output, this is truncated to the low-order 32 bytes for inclusion in the
 * CTL. 
 *
 * @property {CtlRootCaEntry[]} rootCaRemove contains the list of root CA certificates that are
 * valid (that is, not expired) on the effective date and are not approved, as
 * of the effective date, to issue certificates or carry out other
 * activities. If the root certificate is signed with a hash function
 * with a 48 octet output, this is truncated to the low-order 32 bytes for
 * inclusion in the CTL. This field is to be considered informational as a
 * certificate that is not included in rootCaApprove is not valid even if it
 * does not appear in rootCaRemove. 
 *
 * @property {number} quorum contains the quorum, that is, the number of the electors
 * required to sign the next CTL with the same ElectorGroupId value for that
 * CTL to be trusted. If this field is absent, the quorum for the next CTL is
 * equal to the quorum for the current CTL.
 */
 export class FullIeeeTbsCtl extends Sequence([ 
  {name:"type"            ,type:Ieee1609dot2dot1MsctlType},
  {name:"electorGroupId"  ,type:ElectorGroupId},
  {name:"sequenceNumber"  ,type:CtlSequenceNumber},
  {name:"effectiveDate"   ,type:Time32},
  {name:"electorApprove"  ,type:SequenceOf(CtlElectorEntry)},
  {name:"electorRemove"   ,type:SequenceOf(CtlElectorEntry)},
  {name:"rootCaApprove"   ,type:SequenceOf(CtlRootCaEntry)},
  {name:"rootCaRemove"    ,type:SequenceOf(CtlRootCaEntry)},
  {extension:true},
  {name:"quorum"          , type:Integer()}
]){}

 /**
 * @class MultiSignedCtl
 *
 * @brief This structure a certificate trust list (CTL) signed by multiple
 * signers, the electors. An overview of this structure is as follows:
 *
 * @property {Ieee1609dot2dot1MsctlType} type contains the type of the multi-signed CTL. Only one type of
 * multi-signed CTL is supported in this version of this document.
 *
 * @property {FullIeeeTbsCtl} tbsCtl contains the CTL contents.
 *
 * @property {Certificate[]} unsigned contains data that are associated with the CTL and that
 * are not included directly in tbsCtl. For example, if the type is
 * fullIeeeCtlType, the FullIeeeTbsCtl contains the hashes of the
 * certificates, and the certificates themselves are contained in unsigned.
 *
 * @property {CtlSignatureSpdu[]} signatures contains the signatures. How the signatures are
 * calculated is specified in the definition of ToBeSignedCtlSignature. The
 * number of signatures shall be no more than the number of electors. Each
 * signature shall have been generated by a distinct elector.
 */
  export class MultiSignedCtl extends Sequence([
    {name:"type", type:Ieee1609dot2dot1MsctlType},
    {name:"tbsCtl", type:OpenType([
      {name:"fullCtl", type: FullIeeeTbsCtl}
    ], "type")},
    {name:"unsigned", type:SequenceOf(Certificate)},
    {name:"signatures", type:SequenceOf(CtlSignatureSpdu)}
  ]){}

/**
 * @class ToBeSignedCtlSignature
 *
 * @brief This structure contains the CTL-instance-specific information used
 * to generate a signature on the CTL. An overview of this structure is as
 * follows:
 *
 * @property {ElectorGroupId} electorGroupId contains the ElectorGroupId that appears in the CTL.
 *
 * @property {Ieee1609dot2dot1MsctlType} ctlType identifies the type of the CTL.
 *
 * @property {CtlSequenceNumber} sequenceNumber contains the sequence number of the CTL being signed.
 *
 * @property {HashedId48} tbsCtlHash contains the hash of the C-OER encoded tbsCtl field
 * in the MultiSignedCtl. The hash is calculated using the same hash
 * algorithm that is used to generate the signature on this structure when it
 * is contained in a CtlSignatureSpdu. This algorithm can be determined from
 * the headers of the CtlSignatureSpdu.
 */
 export class ToBeSignedCtlSignature extends Sequence([
  {name:"electorGroupId"  ,type:ElectorGroupId},
  {name:"ctlType"         ,type:Ieee1609dot2dot1MsctlType},
  {name:"sequenceNumber"  ,type:CtlSequenceNumber},
  {name:"tbsCtlHash"      ,type:HashedId48}
]){}

/**
 * @class CtlInfoStatus
 *
 * @brief This structure contains the status information for a CTL.
 *
 * @property {ElectorGroupId} electorGroupId contains the elector group ID of the CTL.
 *
 * @property {CtlSequenceNumber} sequenceNumber contains the sequence number of the CTL.
 *
 * @property {Time32} lastUpdate contains the time of the last update of the CTL.
 */
 export class CtlInfoStatus extends Sequence([
  {name:"electorGroupId"  ,type:ElectorGroupId},
  {name:"sequenceNumber"  ,type:CtlSequenceNumber},
  {name:"lastUpdate"      ,type:Time32},
  {extension:true}
 ]) {}

/**
 * @class CrlInfoStatus
 *
 * @brief This structure contains the status information for a CRL.
 *
 * @property {} cracaId contains the CRACA ID of the CRL.
 *
 * @property {} series contains the CRL series of the CRL.
 *
 * @property {} issueDate contains the time of the last update of the CRL.
 */
 export class CrlInfoStatus extends Sequence([
  {name:"cracaId"    ,type:HashedId8},
  {name:"series"     ,type:CrlSeries},
  {name:"issueDate"  ,type:Time32},
  {extension:true}
]){}

/**
 * @class MaInfoStatus
 *
 * @brief This structure contains the status information for an MA's
 * certificate.
 *
 * @property {Psid[]} psids contains the PSIDs associated with the misbehavior that is to
 * be reported to that MA.
 *
 * @property {Time32} updated contains the time of the last update of the MA's certificate.
 */
 export class MaInfoStatus extends Sequence([
  {name:"psids"    ,type:SequenceOf(Psid)},
  {name:"updated"  ,type:Time32},
  {extension:true}
]){}

/**
 * @class CertificateManagementInfoStatus
 *
 * @brief This structure contains the status of different certificate
 * management information, including CRLs, CTLs, and individual certificates
 * of CAs, MAs, and the RA.
 *
 * @property {CrlInfoStatus[]} crl contains the status information for CRLs.
 *
 * @property {CtlInfoStatus[]} ctl contains the status information for CTLs.
 *
 * @property {Time32} caCcf contains the time of the last update of any of the CA 
 * certificates in the CCF.
 *
 * @property {MaInfoStatus} ma contains the status information for MA certificates.
 *
 * @property {?Time32} ra contains the time of the last update of the RA's certificate.
 * It is omitted if this structure is not sent by an RA.
 */
 export class CertificateManagementInfoStatus extends Sequence([
  {name:"crl"    ,type:SequenceOf(CrlInfoStatus)},
  {name:"ctl"    ,type:SequenceOf(CtlInfoStatus)},
  {name:"caCcf"  ,type:Time32},
  {name:"ma"     ,type:SequenceOf(MaInfoStatus)},
  {name:"ra"     ,type:Time32, optional:true},
  {extension:true}
]){}

/**
 * @class CertManagementPdu
 *
 * @brief This is the parent structure for all SCMS component certificate
 * management structures. An overview of this structure is as follows:
 *
 * @property {CompositeCrl} compositeCrl contains zero or more SecuredCrl as defined in IEEE
 * Std 1609.2, and the CTL.
 *
 * @property {CertificateChain} certificateChain contains a collection of certificates and the CTL.
 * 
 * @property {MultiSignedCtl} multiSignedCtl contains the CTL signed by multiple
 * signers, the electors.
 *
 * @property {ToBeSignedCtlSignature} tbsCtlSignature contains the CTL-instance-specific information used
 * to generate a signature on the CTL.
 * 
 * @property {CertificateManagementInfoStatus} infoStatus
 */
  export class CertManagementPdu extends Choice([
    {name:"compositeCrl"      ,type:CompositeCrl},
    {name:"certificateChain"  ,type:CertificateChain},
    {name:"multiSignedCtl"    ,type:MultiSignedCtl},
    {name:"tbsCtlSignature"   ,type:ToBeSignedCtlSignature}, 
    {name:"infoStatus"        ,type:CertificateManagementInfoStatus},
    {extension:true}
  ]){}
 