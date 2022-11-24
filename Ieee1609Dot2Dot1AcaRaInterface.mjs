/*
IMPORTS
  HashAlgorithm,
  HashedId8,
  LaId,
  PublicEncryptionKey,
  Time32,
  Uint8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  base(1) base-types(2) major-version-2(2) minor-version-3(3)}
WITH SUCCESSORS

  CertificateType,
  ToBeSignedCertificate
FROM Ieee1609Dot2 {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  base(1) schema(1) major-version-2(2) minor-version-4(4)}
WITH SUCCESSORS

  AcaEeCertResponsePlainSpdu,
  AcaEeCertResponsePrivateSpdu,
  AcaEeCertResponseCubkSpdu,
  Ieee1609Dot2Data-SymmEncryptedSingleRecipient
FROM Ieee1609Dot2Dot1Protocol {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  extension-standards(255) dot1(1) interfaces(1) protocol(17) 
  major-version-2(2)  minor-version-2(2)}
WITH SUCCESSORS
;
*/

import { Uint8, Choice, Sequence, BitString, OctetString } from "asnjs"
import {Time32, Certificate} from "Ieee1609Dot2js"
import {Ieee1609Dot2Data_Encrypted} from "./Ieee1609Dot2Extension.mjs"

/** 
 * @class RaAcaCertRequestFlags
 *
 * @brief This structure is used to convey information from the RA to the ACA 
 * about operations to be carried out when generating the certificate. For 
 * more details see the specification of RaAcaCertRequest.
 * @property {boolean} butterflyExplicit
 * @property {cubk} butterflyExplicit
 */
  export class RaAcaCertRequestFlags extends BitString(8) {
    get butterflyExplicit() {return this[0]}
    set butterflyExplicit(v) {this[0]=v}
    get cubk() {return this[1]}
    set cubk(v) {this[1]=v}
  }

/** 
 * @class PreLinkageValue
 *
 * @brief This structure contains an individual prelinkage value. It is an
 * octet string of length 9 octets.
 */
 class PreLinkageValue extends OctetString(9){}
 
 /** 
 * @class EncryptedIndividualPLV
 *
 * @brief This structure contains an individual prelinkage value encrypted by
 * the LA for the ACA using the shared secret key. An overview of this
 * structure is as follows:
 *
 * <br><br>NOTE: How the ACA obtains the shared symmetric key and how the RA 
 * associates the encPlv1 and encPlv2 with the correct certificate request are
 * outside the scope of this document.
 *
 * @property {Uint8} version contains the current version of the structure. 
 *
 * @property {LaId} laId contains the ID of the LA that created the prelinkage value.
 * See Annex D for further discussion of LA IDs.
 *
 * @property {Ieee1609Dot2Data} encPlv contains the encrypted individual prelinkage value, that is, 
 * the ciphertext field decrypts to a PreLinkageValue. It contains a pointer 
 * (hash of the shared symmetric key) to the used shared secret encryption key.
 */
  class EncryptedIndividualPLV extends Sequence([
    {name:"version"  , type:Uint8},
    {name:"laId"     , type:LaId},
    {name:"encPlv"   , type:Ieee1609Dot2Data_Encrypted(PreLinkageValue)}
  ]){}
  
/** 
 * @class LinkageInfo
 *
 * @brief This structure contains parameters needed to generate a linkage
 * value for a given (EE, i, j). An overview of this structure is as follows:
 *
 * <br><br>NOTE: See Annex D for further discussion of LAs.
 *
 * @property {EncryptedIndividualPLV} encPlv1 contains the EncryptedIndividualPLV from one of the LAs.
 *
 * @property {EncryptedIndividualPLV} encPlv2 contains the EncryptedIndividualPLV from the other LA.
 */
 class LinkageInfo extends Sequence([
  {name:"encPlv1", type:EncryptedIndividualPLV},
  {name:"encPlv2", type:EncryptedIndividualPLV},
  {extension:true}
]){}

/** 
 * @class RaAcaCertRequest
 *
 * @brief This structure contains parameters needed to request an individual 
 * authorization certificate. An overview of this structure is as follows:
 *
 * <br><br>NOTE 1: In the case where the butterfly key mechanism is used to set
 * certEncKey, the value of j is not communicated to the ACA. However, the EE
 * that receives the certificate response can only decrypt the response if it
 * knows j. The RA is therefore anticipated to store j so that it can be
 * associated with the appropriate certificate response.
 *
 * <br><br>NOTE 2: The cracaId and crlSeries are set to the indicated values
 * in the request. The ACA replaces these values with the appropriate values
 * in the response.
 *
 * <br><br>NOTE 3: The ACA is not bound by the contents of the request and can
 * issue certificates that are different from those requested, if so directed
 * by policy.
 *
 * @property {Uint8} version contains the current version of the structure.
 * 
 * @property {Time32} generationTime contains the generation time of RaAcaCertRequest.
 *
 * @property {CertificateType} type indicates whether the request is for an explicit or implicit
 * certificate (see 4.1.1, 4.1.3.3.1).
 * 
 * @property {RaAcaCertRequestFlags} flags contains the flags related to the use of the butterfly key  
 * mechanism, and provides the following instructions to the ACA as to how 
 * to generate the response:
 * <ol>
 * <li> If the flag butterflyExplicit is set, the request is valid only if
 * the type field is set to explicit. In this case, the ACA uses the
 * butterfly key derivation for explicit certificates as specified in 9.3.
 * The field tbsCert.verifyKeyIndicator.verificationKey is used by the ACA as
 * the cocoon public key for signing. The field privateKeyInfo in the
 * corresponding AcaEeCertResponse is used by the EE as the random integer to
 * recover the butterfly private key for signing.</li>
 *
 * <li> If the flag cubk is set, the request is valid only if the certEncKey
 * field is absent. In this case, the ACA uses the compact unified variation
 * of the butterfly key mechanism as specified in 9.3. This means that the
 * ACA generates an AcaEeCertResponseCubkSpdu instead of an
 * AcaEeCertResponsePrivateSpdu, and the response is valid only if the ACA
 * certificate has the flag cubk set.</li>
 * </ol>
 *
 * @property {LinkageInfo} [linkageInfo] contains the encrypted prelinkage values needed to
 * generate the linkage value for the certificate. If linkageInfo is present,
 * the field tbsCert.id is of type LinkageData, where the iCert field is set
 * to the actual i-period value and the linkage-value field is set to a dummy
 * value to be replaced by the ACA with the actual linkage value. The
 * encrypted prelinkage values are encrypted for the ACA by the LAs.
 *
 * @property {PublicEncryptionKey} [certEncKey] is used in combination with flags.cubk to indicate
 * the type of response that is expected from the ACA. It is as follows:
 * <ol>
 * <li> Absent and flags.cubk is not set if the ACA's response doesn't need
 * to be encrypted. In this case, the ACA responds with
 * AcaEeCertResponsePlainSpdu.</li>
 *
 * <li> Absent and flags.cubk is set if the ACA's response is to be encrypted
 * with the verification key from the request and not signed. In this case,
 * the ACA responds with AcaEeCertResponseCubkSpdu.</li>
 *
 * <li> Present and flags.cubk is not set if the ACA's response is to be
 * encrypted with certEncKey and then signed by the ACA. In this case, the
 * ACA responds with AcaEeCertResponsePrivateSpdu.</li>
 * </ol>
 *
 * @property {ToBeSignedCertificate} tbsCert contains parameters of the requested certificate. The
 * certificate type depends on the field type, as follows:   
 * <ol>
 * <li> If type is explicit, the request is valid only if 
 * tbsCert.verifyKeyIndicator is a verificationKey.</li>
 *
 * <li> If type is implicit, the request is valid only if
 * tbsCert.verifyKeyIndicator is a reconstructionValue.</li>
 * </ol>
 */
 export class RaAcaCertRequest extends Sequence([
  {name:"version"         , type:Uint8},
  {name:"generationTime"  , type:Time32},
  {name:"type"            , type:CertificateType},
  {name:"flags"           , type:RaAcaCertRequestFlags},
  {name:"linkageInfo"     , type:LinkageInfo, optional:true},
  {name:"certEncKey"      , type:PublicEncryptionKey, optional:true},
  {name:"tbsCert"         , type:ToBeSignedCertificate},
  {extension:true}
]){}

/** 
 * @class AcaResponse
 *
 * @brief This structure contains the certificate for the EE in a suitable
 * form as determined from the corresponding RaAcaCertRequestSPDU. In this
 * structure: 
 *
 * @property {AcaEeCertResponsePlainSpdu} [plain] contains the certificate for the EE in plain, that is, without
 * encryption or signature. This choice is used only when the field
 * certEncKey is absent and flags.cubk is not set in the corresponding
 * RaAcaCertRequest.
 *
 * @property {AcaEeCertResponsePrivateSpdu} [private] contains the certificate for the EE in an encrypted then
 * signed form to protect the EE's privacy from the RA. This choice is used
 * only when the field certEncKey is present and flags.cubk is not set in the
 * corresponding RaAcaCertRequest.
 *
 * @property {AcaEeCertResponseCubkSpdu} [cubk] contains the certificate for the EE in an encrypted form. This
 * choice is used only when the field certEncKey is absent and flags.cubk is
 * set in the corresponding RaAcaCertRequest.
 */
 export class AcaResponse extends Choice([
  {name:"plain"    ,type:AcaEeCertResponsePlainSpdu},
  {name:"private"  ,type:AcaEeCertResponsePrivateSpdu},
  {name:"cubk"     ,type:AcaEeCertResponseCubkSpdu},
  {extension:true}
]){}

  /** 
 * @class AcaRaCertResponse
 *
 * @brief This structure contains a certificate response by the ACA,
 * encapsulated for consumption by the EE, as well as associated data for
 * consumption by the RA. The response is of form AcaEeCertResponsePlainSpdu,
 * AcaEeCertResponsePrivateSpdu, or AcaEeCertResponseCubkSpdu, and is
 * generated in response to a successful RaAcaCertRequestSpdu. In this
 * structure: 
 *
 * @property {Uint8} version contains the current version of the structure.
 *
 * @property {Time32} generationTime contains the generation time of AcaRaCertResponse.
 *
 * @property {HashedId8} requestHash contains the hash of the corresponding 
 * RaAcaCertRequestSPDU.
 *
 * @property {AcaResponse} acaResponse contains the certificate for the EE in a suitable form
 * as determined from the corresponding RaAcaCertRequestSPDU.
 */
  export class AcaRaCertResponse extends Sequence([
    {name:"version"        ,type:Uint8},
    {name:"generationTime" ,type:Time32},
    {name:"requestHash"    ,type:HashedId8},
    {name:"acaResponse"    ,type:AcaResponse},
    {extension:true}
  ]){}

/** 
 * @class AcaRaInterfacePDU
 *
 * @brief This is the parent structure for all structures exchanged between
 * the ACA and the RA. An overview of this structure is as follows:
 *
 * @property {RaAcaCertRequest} raAcaCertRequest contains the request for an authorization 
 * certificate from the RA to the ACA on behalf of the EE.
 *
 * @property {AcaRaCertResponse} acaRaCertResponse contains the ACA's response to RaAcaCertRequest.
 */
 export class AcaRaInterfacePdu extends Choice([
  {name: "raAcaCertRequest", type:RaAcaCertRequest},
  {name:"acaRaCertResponse", type:AcaRaCertResponse},
  {extension:true}
]){}
