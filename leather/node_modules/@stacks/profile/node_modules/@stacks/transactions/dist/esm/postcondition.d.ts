import { PostCondition } from './postcondition-types';
import { PostConditionWire } from './wire';
export declare function postConditionToWire(postcondition: PostCondition): PostConditionWire;
export declare function wireToPostCondition(wire: PostConditionWire): PostCondition;
export declare function postConditionToHex(postcondition: PostCondition): string;
