import {Uint8, BitString, OctetString, Choice, Sequence, SequenceOf } from "asnjs"
import {Time32, IValue, HashAlgorithm} from "Ieee1609Dot2js";
import {Ieee1609Dot2Data_Unsecured, Ieee1609Dot2Data_Signed} from "./Ieee1609Dot2Extension.mjs"
/**
 * @class AcpcTreeId
 *
 * @brief This is an 8 byte string that identifies an ACPC tree series. It is
 * required to be globally unique within the system and is the same for all
 * ACPC tree instances within the ACPC tree series. Registration of AcpcTreeId
 * values is managed by the IEEE RA; see http://standards.ieee.org/regauth. A
 * list of assigned AcpcTreeId values is provided in L.2.
 */
 export class AcpcTreeId extends OctetString(8){}

/**
 * @class AcpcPsid
 * @type {number}
 * @brief This is the PSID used to indicate activities in ACPC as specified in
 * this document.
 */
  export const AcpcPsid = 2113696;

/**
 * @class AcpcNodeValue
 *
 * @brief This is a 16 byte string that represents the value of a node in the
 * ACPC tree.
 */
  export class AcpcNodeValue extends OctetString(16){}


/**
 * @class IndividualAprv
 *
 * @brief This structure contains an individual APrV. An overview of this
 * structure is as follows:
 *
 * @property {Uint8} version contains the current version of the structure.
 *
 * @property {Time32} generationTime contains the generation time of IndividualAprv.
 *
 * @property {IValue} currentI contains the i-value associated with the batch of
 * certificates.
 *
 * @property {AcpcTreeId} acpcTreeId contains an identifier for the CAM creating this binary
 * tree.
 *
 * @property {iBitString} nodeId contains the identifier of the node.
 *
 * @property {AcpcNodeValue} nodeValue contains the value of the node.
 */
  export class IndividualAprv extends Sequence([
    {name:"version"         , type:Uint8 },
    {name:"generationTime"  , type:Time32},
    {name:"currentI"        , type:IValue},
    {name:"acpcTreeId"      , type:AcpcTreeId},
    {name:"nodeId"          , type:BitString()},
    {name:"nodeValue"       , type:AcpcNodeValue},
    {extension:true}
  ]){}

/**
 * @class AprvHashCalculationInput
 *
 * @brief This structure, C-OER encoded, is the input to the hash function to
 * calculate child node values from a parent node. By including the ID fields
 * it "firewalls" the hash function so that an attacker who inverts the hash
 * has only found the hash preimage for a specific node, in a specific tree,
 * for a specific time period. An overview of this structure is as follows:
 *
 * @property {Uint8} version contains the current version of the structure.
 *
 * @property {AcpcTreeId} acpcTreeId contains an identifier for this ACPC tree series.
 *
 * @property {IValue} acpcPeriod contains an identifier for the time period for this tree.
 * If the certificates for which this set of APrVs are intended have an IValue
 * field, acpcPeriod in this structure shall be equal to the IValue field in
 * the certificates. How the RA and the CAM synchronize on this value is
 * outside the scope of this document.
 *
 * @property {iBitString} childNodeId contains a bit string of length l encoding the node
 * location within the l'th level. 
 *
 * @property {iOctetString} parentNodeValue contains the value of the parent node.
 */
 export class AprvHashCalculationInput extends Sequence([
  {name:"version"          , type:Uint8},
  {name:"acpcTreeId"       , type:AcpcTreeId},
  {name:"acpcPeriod"       , type:IValue},
  {name:"childNodeId"      , type:BitString()},
  {name:"parentNodeValue"  , type:OctetString(16)},
  {extension:true}
]){}

/**
 * @class AprvBinaryTree
 *
 * @brief This structure encodes a binary tree. An overview of this structure
 * is as follows:
 *
 * @property {Uint8} version contains the current version of the structure.
 *
 * @property {Time32} generationTime contains the generation time of AprvBinaryTree.
 *
 * @property {IValue} currentI contains the i-value associated with the batch of
 * certificates.
 *
 * @property {AcpcTreeId} acpcTreeId contains an identifier for the CAM creating this binary
 * tree.
 *
 * @property {HashAlgorithmValue} hashAlgorithmId contains the identifier of the hash algorithm used
 * inside the binary tree.
 *
 * @property {BitString} tree contains a bit string indicating which nodes of the tree are 
 * present. It is calculated as specified in 9.5.4.2, and can be used by the
 * EE to determine which entry in nodeValueList to use to derive that EE's
 * APrV as specified in 9.5.2.
 *
 * @property {AcpcNodeValue[]} nodeValueList contains the values of the nodes that are present in 
 * the order indicated by tree.
 */
  export class AprvBinaryTree extends Sequence([
    {name:"version"          ,type:Uint8}, 
    {name:"generationTime"   ,type:Time32},
    {name:"currentI"         ,type:IValue}, 
    {name:"acpcTreeId"       ,type:AcpcTreeId},
    {name:"hashAlgorithmId"  ,type:HashAlgorithm},
    {name:"tree"             ,type:BitString()},
    {name:"nodeValueList"    ,type:SequenceOf(AcpcNodeValue)},
    {extension:true}
  ]){}

/**
 * @class AcpcPdu
 *
 * @brief This structure contains an APrV structure produced by the CAM. An
 * overview of this structure is as follows:
 *
 * @property {AprvBinaryTree} tree contains an AprvBinaryTree.
 *
 * @property {IndividualAprv} aprv contains a single IndividualAprv.
 */
  export class AcpcPdu extends Choice([
    {name:"tree", type:AprvBinaryTree},
    {name:"aprv", type:IndividualAprv},
    {extension:true}
  ]){}

/**
 * @class UnsecuredAprvBinaryTree
 *
 * @brief This is used to wrap an AprvBinaryTree in an Ieee1609Dot2Data for
 * transmission if the policy is that the AprvBinaryTree need not be signed.
 * See 9.5.6 for discussion.
 */
  export class UnsecuredAprvBinaryTree extends Ieee1609Dot2Data_Unsecured (AcpcPdu) {}

/**
 * @class SignedAprvBinaryTree
 *
 * @brief This is used to wrap an AprvBinaryTree in an Ieee1609Dot2Data for
 * transmission if the policy is that the AprvBinaryTree be signed. See 9.5.6
 * for discussion.
 */

  export class SignedAprvBinaryTree extends Ieee1609Dot2Data_Signed (AcpcPdu) {}
/**
 * @class SignedIndividualAprv
 *
 * @brief This is used to wrap an IndividualAprv in an Ieee1609Dot2Data for
 * transmission if the policy is that the IndividualAprv be signed. See 9.5.6
 * for discussion.
 */
  export class SignedIndividualAprv extends Ieee1609Dot2Data_Signed (AcpcPdu) {}

