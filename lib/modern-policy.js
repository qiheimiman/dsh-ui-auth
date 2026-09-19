/**
 * DSH 0.1.5 Remote surface policy — 精简版（仅登录验证，移除多用户隔离）。
 *
 * 本模块原负责按用户隔离会话/工作区数据。精简后仅保留登录状态检查。
 */
export const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
export const nonempty = (value) => typeof value === 'string' && value.length > 0 && value.length <= 256;
/** The single `args` object of a Remote payload, or undefined when malformed. */
export function remoteArgs(payload) {
    if (!object(payload) || Object.keys(payload).length !== 1 || !object(payload.args))
        return undefined;
    return payload.args;
}
export function createModernPolicy(_owners) {
    // 精简版：所有已登录用户都有完全访问权限（单用户模式）
    const session = (_principal, _id) => true;
    const workspace = (_principal, _id) => true;
    return {
        session,
        workspace,
        async authorize(principal, _endpoint, _payload, _stream = false) {
            // 精简版：只要登录就允许所有操作
            return principal !== undefined;
        },
        async result(_principal, _endpoint, value) {
            return value;
        },
        frame(_principal, _endpoint, value, _correlation) {
            return value;
        },
    };
}
