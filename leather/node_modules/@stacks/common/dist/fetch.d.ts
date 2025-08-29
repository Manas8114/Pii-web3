export declare const getFetchOptions: () => RequestInit;
export declare const setFetchOptions: (ops: RequestInit) => RequestInit;
export declare function fetchWrapper(input: RequestInfo, init?: RequestInit): Promise<Response>;
export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;
export interface ClientOpts {
    baseUrl?: string;
    fetch?: FetchFn;
}
export interface ClientParam {
    client?: ClientOpts;
}
export interface RequestContext {
    fetch: FetchFn;
    url: string;
    init: RequestInit;
}
export interface ResponseContext {
    fetch: FetchFn;
    url: string;
    init: RequestInit;
    response: Response;
}
export interface FetchParams {
    url: string;
    init: RequestInit;
}
export interface FetchMiddleware {
    pre?: (context: RequestContext) => PromiseLike<FetchParams | void> | FetchParams | void;
    post?: (context: ResponseContext) => Promise<Response | void> | Response | void;
}
export interface ApiKeyMiddlewareOpts {
    host?: RegExp | string;
    httpHeader?: string;
    apiKey: string;
}
export declare function hostMatches(host: string, pattern: string | RegExp): boolean | RegExpExecArray | null;
export declare function createApiKeyMiddleware({ apiKey, host, httpHeader, }: ApiKeyMiddlewareOpts): FetchMiddleware;
export declare function createFetchFn(fetchLib: FetchFn, ...middleware: FetchMiddleware[]): FetchFn;
export declare function createFetchFn(...middleware: FetchMiddleware[]): FetchFn;
