import { UserWithoutPassword } from "../user/user.interface"
import { AuthRequest } from "./auth.request.dto"
import { Request } from "express"
import { User } from "@prisma/client"

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
    guard: string,
    session?: ISessionData | null,
    userSessions?: string[],
    request?: Request
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

export interface IForgotPasswordContext {
    email: string,
    user?: User,
    resetToken?: string,
    hashedToken?: string,
    expiresAt?: Date
}