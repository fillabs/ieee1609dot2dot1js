import {Ieee1609Dot2Data} from "Ieee1609Dot2js"

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
export function Ieee1609Dot2Data_Unsecured (inner) {
    var C = class Ieee1609Dot2Data_Unsecured  extends Ieee1609Dot2Data {
        static from_oer(dc) {
            let outer = super.from_oer(dc);
            try {
                outer.content.unsecuredData.content = inner.from_oer(outer.content.unsecuredData.dataCursor());
            } catch(e){

            }
            return outer;
        }
    };
    if(inner.fields)
        C.innerFields = inner.fields;
    return C;
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
 export function Ieee1609Dot2Data_Signed ( inner ) {
    var C = class Ieee1609Dot2Data_Signed extends Ieee1609Dot2Data {
        static from_oer(dc) {
            let outer = super.from_oer(dc);
            try {
                outer.content.signedData.tbsData.payload.data.content = inner.from_oer(outer.content.signedData.tbsData.payload.data.dataCursor());
            } catch(e){

            }
            return outer;
        }
    }
    if(inner.fields)
        C.innerFields = inner.fields;
    return C;
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
 export function Ieee1609Dot2Data_CertRequest ( inner ) {
    var C = class Ieee1609Dot2Data_CertRequest extends Ieee1609Dot2Data {
        static from_oer(dc) {
            /** @type {Ieee1609Dot2Data} */
            let outer = super.from_oer(dc);
            try {
                outer.content.signedCertificateRequest.content = inner.from_oer(outer.content.signedCertificateRequest.content.dataCursor());
            } catch(e){
            }
            return outer;
        }
    };
    if(inner.fields)
        C.innerFields = inner.fields;
    return C;
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
export function Ieee1609Dot2Data_Encrypted ( inner ) {
    var C = class Ieee1609Dot2Data_Encrypted extends Ieee1609Dot2Data {
    }
    if(inner.fields)
        C.innerFields = inner.fields;
    return C;
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
export function Ieee1609Dot2Data_SignedEncrypted( inner ) {
    return Ieee1609Dot2Data_Encrypted(
        Ieee1609Dot2Data_Signed(inner));
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
export function Ieee1609Dot2Data_EncryptedSigned( inner ) {
    return Ieee1609Dot2Data_Signed(
        Ieee1609Dot2Data_Encrypted(inner));
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
export function Ieee1609Dot2Data_SignedCertRequest( inner ) {
    return Ieee1609Dot2Data_Signed(
        Ieee1609Dot2Data_CertRequest(inner));
}

/**
 * @param {*} inner 
 * @returns {Ieee1609Dot2Data}
 */
 export function Ieee1609Dot2Data_SignedEncryptedCertRequest( inner ) {
    return Ieee1609Dot2Data_Encrypted(
        Ieee1609Dot2Data_Signed(
            Ieee1609Dot2Data_CertRequest(inner)));
}

export function Ieee1609Dot2Data_SymmEncryptedSingleRecipient( inner ) {
    return Ieee1609Dot2Data_Encrypted(inner);
}