/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export declare function registerFid(account: Account, recoveryAddress?: string | undefined | null): Promise<number>
export declare function ownerOfFname(fname: string): Promise<number | null>
export declare function transferFname(account: Account, fname: string, toFid: number): Promise<boolean>
export declare function fidOf(address: string): Promise<number>
export declare class Account {
  static fromMnemonic(mnemonic: string): Account
  static fromPrivateKeyHex(privateKeyHex: string): Account
}
