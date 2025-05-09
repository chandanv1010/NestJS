import { UserWithoutPassword } from "../user/user.interface"
import { AuthRequest } from "./auth.request.dto"

export interface ILoginResponse {
    accessToken: string,
    expiresAt: number,
    tokenType: string,
    crsfToken: string
}

export interface IJwtPayload {
    sub: string,
    exp: number,
    iat: number,
    guard: string
}

export interface ITokenContext {
    user: UserWithoutPassword | null, 
    accessToken?: string,
    refreshToken?: string,
    crsfToken?: string,
    sessionId?: string,
    deviceId: string,
    authRequest: AuthRequest,
    guard: string
}

export interface ISessionData {
    userId: string,
    deviceId: string,
    refreshToken: string,
    crsfToken: string,
    createdAt: number,
    lastUsed: number,
    wasUsed: boolean,
    isRevoked: boolean,
    expiresAt: number
}