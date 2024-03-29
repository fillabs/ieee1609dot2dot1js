/*
DEFINITIONS AUTOMATIC TAGS ::= BEGIN

EXPORTS ALL;

IMPORTS
  EccP256CurvePoint,
  HashedId8,
  IValue,
  Uint8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  base(1) base-types(2) major-version-2(2) minor-version-3(3)}
WITH SUCCESSORS
;
*/

import { OctetString, SequenceOf, Sequence, Choice } from "asnjs"
import {EccP256CurvePoint, HashedId8, IValue} from "Ieee1609Dot2js"
/**
 * @class RaCamBatchRequest
 *
 * @brief This structure contains parameters needed to request a blinded batch
 * of keys for the EE during ACPC enrollment. An overview of this structure
 * is as follows:
 *
 * @property {Uint8} version contains the current version of the structure. 
 *
 * @property {iOctetString} eeId contains the EE's ID generated by the RA for the production of
 * ACPC batch keys by the CAM. 
 *
 * @property {IValue[]} periodList contains the list of i-periods covered by the batch.
 */
  export class RaCamBatchRequest extends Sequence ([
    {name:"version"     ,type:Uint8},
    {name:"eeId"        ,type:OctetString(5)},
    {name:"periodList"  ,type:SequenceOf(IValue)},
    {extension:true}
  ]){}

/**
 * @class BlindedKey
 *
 * @brief This is a blinded ACPC encryption key produced by the CAM.
 */
export class BlindedKey extends EccP256CurvePoint {}

/**
 * @class CamRaBatchResponse
 *
 * @brief This structure contains a blinded batch of keys for the EE during
 * ACPC enrollment. An overview of this structure is as follows:
 *
 * @property {UInt8} version contains the current version of the structure. 
 *
 * @property {HashedId8} requestHash contains the hash of the corresponding request 
 * RaCamBatchRequest.
 * 
 * @property {BlindedKey[]} batch contains a sequence of blinded keys, each mapped to one 
 * IValue from the periodList field of the request.
 */
  export class CamRaBatchResponse extends Sequence ([
    {name:"version"      , type:Uint8},
    {name:"requestHash"  , type:HashedId8},
    {name:"batch"        , type:SequenceOf(BlindedKey)},
    {extension:true}
  ]){}

/**
 * @class CamRaInterfacePDU
 *
 * @brief This is the parent structure for all structures exchanged between
 * the CAM and the RA during ACPC enrollment. An overview of this structure
 * is as follows:
 *
 * @property {RaCamBatchRequest} raCamBatchRequest contains the ACPC blinded key batch request sent
 * by the RA to the CAM.
 *
 * @property {CamRaBatchResponse} camRaBatchResponse contains the CAM's response to RaCamBatchRequest.
 */
  export class CamRaInterfacePdu extends Choice ([
    {name:"raCamBatchRequest"  , type:RaCamBatchRequest},
    {name:"camRaBatchResponse" , type:CamRaBatchResponse},
    {extension:true}
  ]){}

