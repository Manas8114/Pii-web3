import { StringAsciiCV, StringUtf8CV } from '../types';
export declare const stringAsciiCV: (data: string) => StringAsciiCV;
export declare const stringUtf8CV: (data: string) => StringUtf8CV;
export declare const stringCV: (data: string, encoding: 'ascii' | 'utf8') => StringAsciiCV | StringUtf8CV;
