import { ClarityValue } from '.';
import { BytesReader } from '../BytesReader';
export declare function deserializeCV<T extends ClarityValue = ClarityValue>(serializedClarityValue: BytesReader | Uint8Array | string): T;
