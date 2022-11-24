import {Uint8, Uint16, Uint32, Choice, Sequence, SequenceOf } from 'asnjs';
import {LaId, LinkageSeed, CrlSeries, HashedId8, HashedId10, Time32} from 'Ieee1609Dot2js';

/**
 * @property {Uint8} priority
 */
class CrlPriorityInfo extends Sequence([
    {name:"priority", type:Uint8,  optional:true },
    {extension:true}
]){}

/**
    @property {Uint8} version
    @property {CrlSeries} crlSeries
    @property {HashedId8} cracaId
    @property {Time32} issueDate
    @property {Time32} nextCrl
    @property {CrlPriorityInfo} priorityInfo
    @property {{
        fullHashCrl:   (ToBeSignedHashIdCrl|undefined),
        deltaHashCrl:  (ToBeSignedHashIdCrl|undefined)
        fullLinkedCrl: (ToBeSignedLinkageValueCrl|undefined)
        deltaLinkedCrl:(ToBeSignedLinkageValueCrl|undefined)
    }} typeSpecific
 */
export class CrlContents extends Sequence([
    { name: "version"            , type: Uint8},
    { name: "crlSeries"          , type: CrlSeries},
    { name: "cracaId"            , type: HashedId8},
    { name: "issueDate"          , type: Time32},   
    { name: "nextCrl"            , type: Time32},  
    { name: "priorityInfo"       , type: CrlPriorityInfo},
    { name: "typeSpecific"       ,
      type: Choice([
        { name: "fullHashCrl"          , type: ToBeSignedHashIdCrl},            
        { name: "deltaHashCrl"         , type: ToBeSignedHashIdCrl},
        { name: "fullLinkedCrl"        , type: ToBeSignedLinkageValueCrl},
        { name: "deltaLinkedCrl"       , type: ToBeSignedLinkageValueCrl},
        { extension: true}
    ])}
]){}
  

/**
 * @property {HashedId10} id
 * @property {Time32} expiry
 */
export class HashBasedRevocationInfo extends Sequence([
    {name:"id", type: HashedId10},
    {name:"expiry", type:Time32}
]){}

/**
 * @property {Uint32} crlSerial
 * @property {HashBasedRevocationInfo[]} entries
 */
export class ToBeSignedHashIdCrl extends Sequence([
    {name:"crlSerial", type: Uint32},
    {name:"entries", type: SequenceOf(HashBasedRevocationInfo)},
    {extension:true}
]){}

/**
 * @property {LinkageSeed} linkageSeed1
 * @property {LinkageSeed} linkageSeed2
 */
 class IndividualRevocation extends Sequence([
    {name: "linkageSeed1", type: LinkageSeed},
    {name: "linkageSeed2", type: LinkageSeed},
    {extension:true}
]){}

/**
 * @property {Uint16} iMax
 * @property {IndividualRevocation[]contents}
 */
class IMaxGroup extends Sequence([
    {name:"iMax", type:Uint16},
    {name:"contents", type:SequenceOf(IndividualRevocation)},
    {extension:true}
]){}

/**
 * @property {LaId} la1Id
 * @property {LaId} la2Id
 * @property {IMaxGroup[]}contents
 */
 class LAGroup extends Sequence([
    {name:"la1Id", type:LaId},
    {name:"la2Id", type:LaId},
    {name:"contents", type:SequenceOf(IMaxGroup)},
    {extension:true}
]){}

/**
 * @property {Uint8}jmax
 * @property {LAGroup[]}contents
 */
 class JMaxGroup extends Sequence([
    {name:"jmax", type:Uint8},
    {name:"contents", type:SequenceOf(LAGroup)},
    {extension:true}
]){}

/**
 * @property {IValue} iRev
 * @property {Uint8} indexWithinI
 * @property {JMaxGroup[]}individual
 * @property {GroupCrlEntry}groups
 */
class ToBeSignedLinkageValueCrl extends Sequence([
    {name:"iRev", type: IValue},
    {name:"indexWithinI", type:Uint8},
    {name:"individual", type: SequenceOf(JMaxGroup), optional:true},
    {name: "groups", type:SequenceOf(GroupCrlEntry), optional:true},
    {extension:true}
]){} 

/**
 * @property {Uint16}iMax
 * @property {LaId} la1Id
 * @property {LinkageSeed} linkageSeed1
 * @property {LaId} la2Id
 * @property {LinkageSeed} linkageSeed2
 */
class GroupCrlEntry extends Sequence([
    {name:"iMax"             ,type:Uint16},
    {name:"la1Id"            ,type:LaId},
    {name:"linkageSeed1"     ,type:LinkageSeed},
    {name:"la2Id"            ,type:LaId},
    {name:"linkageSeed2"     ,type:LinkageSeed},
    {extension:true}
]){}
