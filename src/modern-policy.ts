/**
 * DSH 0.1.5 Remote surface policy — 精简版（仅登录验证，移除多用户隔离）。
 *
 * 本模块原负责按用户隔离会话/工作区数据。精简后仅保留登录状态检查。
 */

/** 已认证的 Principal。 */
export interface Principal {
  readonly username: string
  readonly role: string
}

/** 所有权查询（精简版不再需要）。 */
export interface OwnershipLookup {
  session(id: string): string
  workspace(id: string): string
  sessionExists(id: string): Promise<boolean>
  claimSession(id: string, username: string): Promise<void>
}

/** 任何解码的 JSON 对象。 */
export type JsonObject = Record<string, unknown>

/** 每流关联状态。 */
export interface StreamCorrelation {
  clientId?: string
  login?: string
  events: Set<string>
}

export const object = (value: unknown): value is JsonObject =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

export const nonempty = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= 256

/** The single `args` object of a Remote payload, or undefined when malformed. */
export function remoteArgs(payload: unknown): JsonObject | undefined {
  if (!object(payload) || Object.keys(payload).length !== 1 || !object((payload as JsonObject).args)) return undefined
  return (payload as JsonObject).args as JsonObject
}

export interface ModernPolicy {
  session(principal: Principal, id: unknown): boolean
  workspace(principal: Principal, id: unknown): boolean
  authorize(principal: Principal, endpoint: string, payload: unknown, stream?: boolean): Promise<boolean>
  result(principal: Principal, endpoint: string, value: unknown): Promise<unknown>
  frame(principal: Principal, endpoint: string, value: unknown, correlation: StreamCorrelation): unknown
}

export function createModernPolicy(_owners: OwnershipLookup): ModernPolicy {
  // 精简版：所有已登录用户都有完全访问权限（单用户模式）
  const session = (_principal: Principal, _id: unknown): boolean => true
  const workspace = (_principal: Principal, _id: unknown): boolean => true

  return {
    session,
    workspace,
    async authorize(principal, _endpoint, _payload, _stream = false) {
      // 精简版：只要登录就允许所有操作
      return principal !== undefined
    },
    async result(_principal, _endpoint, value) {
      return value
    },
    frame(_principal, _endpoint, value, _correlation) {
      return value
    },
  }
}
