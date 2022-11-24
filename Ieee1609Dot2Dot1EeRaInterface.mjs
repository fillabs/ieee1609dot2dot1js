/** 
 * @brief EE - RA Interface
 * @module Ieee1609Dot2Dot1EeRaInterface
 * @version 2.2
 * NOTE: Section references in this file are to clauses in IEEE Std
 * 1609.2.1 unless indicated otherwise. Full forms of acronyms and
 * abbreviations used in this file are specified in 3.2.
 */

import {HashedId8, IValue, Time32, CertificateType, PublicEncryptionKey} from "Ieee1609Dot2js"
import {EeEcaCertRequestSpdu} from "./Ieee1609Dot2Dot1Protocol.mjs"
import {AcpcTreeId} from "./Ieee1609Dot2Dot1Acpc.mjs"
import { OctetString, Uint8, UTF8String } from "EtsiTs102941js/node_modules/Ieee1609Dot2Dot1js/node_modules/asnjs"
import { ToBeSignedCertificate } from "EtsiTs102941js/node_modules/Ieee1609Dot2js"


/**
 * @class RaEeCertInfo
 *
 * @brief This structure is used to create the info file that accompanies a
 * batch of certificates for download as specified in 8.2.3. It is used when
 * certificates were generated using the butterfly key expansion mechanism
 * specified in 9.3. An overview of this structure is as follows:
 *
 * @property {} version contains the current version of the structure. 
 *
 * @property {} generationTime contains the generation time of RaEeCertInfo. 
 *
 * @property {} currentI contains the i-value associated with the batch of
 * certificates.
 *
 * @property {} requestHash contains the hash of the corresponding
 * EeRaCertRequestSpdu. 
 *
 * @property {} nextDlTime contains the time after which the EE should connect to
 * the RA to download the certificates.
 *
 * @property {} acpcTreeId contains the ACPC Tree Id if the certificates were
 * generated using ACPC as specified in 9.5. 
 */
 class RaEeCertInfo extends Sequence([
  {name:"version",         type:Uint8},
  {name:"generationTime",  type:Time32},
  {name:"currentI",        type:IValue},
  {name:"requestHash",     type:HashedId8},
  {name:"nextDlTime",      type:Time32},
  {name:"acpcTreeId",      type:AcpcTreeId,optional:true},
  {extension:true}
]){}

/**
 * @class EeRaDownloadRequest
 *
 * @brief This structure contains parameters needed to request the download of
 * certificates from the RA. An overview of this structure is as follows:
 *
 * @property {Time32} generationTime contains the generation time of EeRaDownloadRequest.
 *
 * @property {UTF8String} filename contains the name of the file requested for download,
 * formed as specified in 8.2.2.
 */
 class EeRaDownloadRequest extends Sequence([
  {name:"generationTime",  type:Time32},
  {name:"filename",        type:UTF8String()},
  {extension:true}
]){}

/**
 * @class RaEeCertAck
 *
 * @brief This structure is used to create the acknowledgement for certificate
 * requests. An overview of this structure is as follows:
 *
 * @property {Uint8} version contains the current version of the structure.
 *
 * @property {Time32} generationTime contains the generation time of RaEeCertAck.
 *
 * @property {HashedId8} requestHash contains the hash of the corresponding 
 * EeRaCertRequestSpdu.
 * 
 * @property {IValue} [firstI] contains the i-value that will be associated with the first
 * certificate or certificate batch that will be made available to the EE. The
 * EE uses this to form the download filename for the download request as
 * specified in 8.2.2.
 *
 * @property {Time32} nextDlTime contains the time after which the EE should connect to
 * the RA to download the certificates.
 */
 class RaEeCertAck extends Sequence([
  {name:"version"         ,type:Uint8},
  {name:"generationTime"  ,type:Time32},
  {name:"requestHash"     ,type:HashedId8}, 
  {name:"firstI"          ,type:IValue, optional:true},
  {name:"nextDlTime"      ,type:Time32},
  {extension:true}
]){}

/**
 * @class ButterflyExpansion
 *
 * @brief This structure contains material used in the butterfly key
 * calculations as specified in 9.3.5.1 and 9.3.5.2. An overview of this
 * structure is as follows:
 *
 * @property {} aes128 indicates that the symmetric algorithm used in the expansion
 * function is AES-128 with the indicated 16 byte string used as the key. 
 */
 class ButterflyExpansion extends Choice ([
  {name:"aes128", type:OctetString(16)},
  {extension:true}
]){}

/**
* @class ButterflyParamsOriginal
*
* @brief This structure contains parameters for the original variation of the
* butterfly key mechanism. An overview of this structure is as follows:
*
* @property {} signingExpansion contains the expansion function for signing.
*
* @property {} encryptionKey contains the caterpillar public key for encryption.
*
* @property {} encryptionExpansion contains the expansion function for encryption.
*/
class ButterflyParamsOriginal extends Sequence([
{name:"signingExpansion"     ,type:ButterflyExpansion},
{name:"encryptionKey"        ,type:PublicEncryptionKey},
{name:"encryptionExpansion"  ,type:ButterflyExpansion}
]){}

/**
 * @class AdditionalParams
 *
 * @brief This structure contains parameters for the butterfly key mechanism.
 * An overview of this structure is as follows:
 *
 * @property {} original contains the parameters for the original variant.
 *
 * @property {} unified contains the expansion function for signing to be used for
 * the unified variant. The caterpillar public key and expansion function for
 * encryption are the same as those for signing.
 *
 * @property {} compactUnified contains the expansion function for signing to be
 * used for the compact unified variant. The caterpillar public key and
 * expansion function for encryption are the same as those for signing. 
 *
 * @property {} encryptionKey contains the public key for encrypting the
 * certificate if the butterfly key mechanism is not used.
 */
  class AdditionalParams extends Choice ([
    {name:"original"        ,type:ButterflyParamsOriginal},
    {name:"unified"         ,type:ButterflyExpansion},  
    {name:"compactUnified"  ,type:ButterflyExpansion},
    {name:"encryptionKey"   ,type:PublicEncryptionKey},
    {extension:true}
  ]){}

/**
 * @class EeRaCertRequest
 *
 * @brief This structure contains parameters needed to request different types 
 * of authorization certificates. An overview of this structure is as follows:
 *
 * <br><br>NOTE 1: In the case where the butterfly key mechanism is used to
 * derive the certificate encryption key, the value j is not communicated to
 * the ACA. However, the EE that receives the certificate response can only
 * decrypt the response if it knows j. The RA is therefore anticipated to
 * store j so that it can be associated with the appropriate certificate
 * response. 
 *
 * <br><br>NOTE 2: The EE uses the type field to indicate whether it is
 * requesting an explicit or an implicit authorization certificate. A policy
 * is anticipated that determines what type of certificate is appropriate for
 * a given set of circumstances (such as PSIDs, other end entity information,
 * locality, {extension:true}) and that if the EE has requested a kind of certificate that
 * is not allowed by policy, the ACA returns an error to the EE. This implies
 * that the certificate issued by the ACA is always of type indicated in the
 * EeRaCertRequest.
 *
 * <br><br>NOTE 3 This document does not specify a method to include an
 * encryptionKey in the requested certificates, if the butterfly key
 * mechanism is used. The EE using such a certificate to sign a message can
 * request an encrypted response using the tbsData.headerInfo.encryptionKey
 * field of the SignedData; see 6.3.9, 6.3.33, 6.3.34, and 6.3.36 of
 * IEEE Std 1609.2 for more details.
 *
 * @property {Uint8} version contains the current version of the structure. 
 *
 * @property {Time32} generationTime contains the generation time of EeRaCertRequest.
 *
 * @property {('explicit|implicit')} type indicates whether the request is for an explicit or implicit
 * certificate (see 4.1.1 and 4.1.4.3.1).
 *
 * @property {ToBeSignedCertificate} tbsCert contains the parameters to be used by the ACA to generate
 * authorization certificate(s).
 * <ol>
 * <li>	id contains the identity information sent by the requester. If the
 * type is LinkageData, the RA replaces that in the certificates with the
 * linkage values generated with the help of the LAs and the ACA; see Annex
 * D.</li> 
 *
 * <li>	validityPeriod contains the requested validity period of the first
 * batch of certificates.</li>
 *
 * <li>	region, assuranceLevel, canRequestRollover, and encryptionKey, if
 * present, contain the information sent by the requester for the requested
 * certificates.</li>
 *
 * <li> verifyKeyIndicator.verificationKey contains the public key
 * information sent by the requester. The verifyKeyIndicator field indicates
 * the choice verificationKey even if type is implicit, as this allows the
 * requester to indicate which signature algorithm and curve they are
 * requesting.</li>
 *
 * <ol>
 * <li> If the certificate issued in response to this request is explicit and
 * butterfly expansion is not used, the value in this field is the
 * verification key that appears in that certificate.</li>
 *
 * <li> If the certificate issued in response to this request is implicit and
 * butterfly expansion is not used, the value in this field is the input
 * public key value for implicit certificate generation.</li>
 *
 * <li> If butterfly expansion is used, that is, if one of (original, unified,
 * compactUnified) options is present in the field additionalParams, the
 * value in this field is combined with the values in the additionalParams
 * field as specified in 9.3.</li>
 * </ol>
 * </ol>
 *
 * @property {AdditionalParams} additionalParams contains relevant parameters for generating the
 * requested certificates using the butterfly key mechanism as specified in
 * 9.3, or for encrypting the certificates without using the butterfly key
 * mechanism. If present, the field tbsCert.verifyKeyIndicator shall be used
 * as the caterpillar public key for signing in the butterfly key mechanism.
 */
  export class EeRaCertRequest extends Sequence([
    {name:"version"           ,type:Uint8},
    {name:"generationTime"    ,type:Time32},
    {name:"type"              ,type:CertificateType},
    {name:"tbsCert"           ,type:ToBeSignedCertificate},
    {name:"additionalParams"  ,type:AdditionalParams, optional:true},
    {extension:true}
  ]){}

/**
 * @class EeRaInterfacePDU
 *
 * @brief This is the parent structure for all structures exchanged between
 * the EE and the RA. An overview of this structure is as follows:
 *
 * <br><br>NOTE: This CHOICE does not include a PDU type for encrypted
 * misbehavior report upload; see 4.1.5.
 *
 * @property {EeRaCertRequest} [eeRaCertRequest] contains the certificate generation request sent by
 * the EE to the RA.
 *
 * @property {RaEeCertAck} [raEeCertAck] contains the RA's acknowledgement of the receipt of
 * EeRaCertRequestSpdu.
 *
 * @property {RaEeCertInfo} [raEeCertInfo] contains the information about certificate download.
 *
 * @property {EeRaDownloadRequest} [eeRaDownloadRequest] contains the download request sent by the EE to
 * the RA.
 *
 * @property {EeEcaCertRequestSpdu} [eeRaSuccessorEnrollmentCertRequest] contains a self-signed request
 * for an enrollment certificate, identical in format to the one submitted
 * for an initial enrollment certificate. (This becomes a request for a
 * successor enrollment certificate by virtue of being signed by the current
 * enrollment certificate.)
 */
 export class EeRaInterfacePdu extends Choice ([
  {name:"eeRaCertRequest"                     ,type:EeRaCertRequest},
  {name:"raEeCertAck"                         ,type:RaEeCertAck},
  {name:"raEeCertInfo"                        ,type:RaEeCertInfo},
  {name:"eeRaDownloadRequest"                 ,type:EeRaDownloadRequest},
  {name:"eeRaSuccessorEnrollmentCertRequest"  ,type:EeEcaCertRequestSpdu},
  {extension:true}
]){}

