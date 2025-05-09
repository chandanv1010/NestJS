/* eslint-disable @typescript-eslint/no-unused-vars */
import { Injectable, InternalServerErrorException, UnauthorizedException, Inject, Logger } from '@nestjs/common';
import { AuthRequest } from './auth.request.dto';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { UserWithoutPassword } from '../user/user.interface';
import { ILoginResponse, IJwtPayload, ITokenContext, ISessionData } from './auth.interface';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { Request } from 'express';
import { ExceptionHandler } from 'src/utils/exception-handler.util';
import { Response } from 'express';
import { UserService } from '../user/user.service';
import { User } from '@prisma/client';

const ACCESS_TOKEN_TIME_TO_LIVE = '1h'
const REFRESH_TOKEN_TIME_TO_LIVE = 30 * 24 * 60 * 60
const MAX_SESSION_PER_USER = 5;
const REFRESH_TOKEN_COOKIE_NAME = 'nestJs_refresh_token';

@Injectable()
export class AuthService {
    
    private readonly logger = new Logger(AuthService.name)


    constructor(
        private readonly prismaService: PrismaService,
        private readonly jwtService: JwtService,
        private readonly userService: UserService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache
    ){
        
    }

    async authenticate(authRequest: AuthRequest, request: Request, guard: string, response: Response): Promise<ILoginResponse> {
        try {
          
            return await this.createAuthContext(authRequest, request, guard)
                            .then(context => this.validateUser(context))
                            .then(context => this.revokeExistingDeviceSession(context))
                            .then(context => this.generateAccessToken(context))
                            .then(context => this.generateRefreshToken(context))
                            .then(context => this.generateCrsfToken(context))
                            .then(context => this.saveSession(context))
                            .then(context => this.authReponse(context, response))
            
        } catch (error) {
            return ExceptionHandler.error(error, this.logger)
        }
    }

    private async createAuthContext(authRequest: AuthRequest, request: Request, guard: string): Promise<ITokenContext> {
        return Promise.resolve({
            authRequest,
            user: null,
            deviceId: this.generateDeviceId(request),
            guard: guard
        })
    }

    private generateDeviceId(request: Request): string {
        const userAgent = request.headers['user-agent'] || 'unknown'
        const ip = request.ip || 'unknown'
        return Buffer.from(`${userAgent}:${ip}`).toString('base64')
    }

    private async revokeExistingDeviceSession(context: ITokenContext): Promise<ITokenContext> {
        const { user, deviceId } = context
        if(!user || !deviceId) return context

        try {
            const userSessions: string[] = await this.cacheManager.get(`user:${user.id}:sessions:${context.guard}`) || []
            let updateSession = [...userSessions]
            for(let i = 0; i < userSessions.length; i++){
                const sessionId = userSessions[i]
                const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}:${context.guard}`)

                if(session && session.deviceId === deviceId){
                    session.isRevoked = true
                    await this.cacheManager.set(`sessions:${sessionId}:${context.guard}`, session)
                    updateSession = updateSession.filter(id => id !== sessionId)

                    this.logger.log(`Đã vô hiệu hóa phiên ${sessionId} trên thiết bị ${deviceId}`)
                }
            }

            if(updateSession.length !== userSessions.length){
                await this.cacheManager.set(`user:${user.id}:sessions:${context.guard}`, updateSession)
            } 
        } catch (error) {
            if(error instanceof Error){
                this.logger.error(`Lỗi trong quá trình xác thực: ${error.message}`, error.stack);
            }
        }
        return context

    }

    private async generateAccessToken(context: ITokenContext): Promise<ITokenContext> {
        if(!context.user) throw new Error("Không có thông tin User trong Context")
        const payload = { sub: context.user.id.toString(), guard: context.guard }
        context.accessToken = await this.jwtService.signAsync(payload, {
            expiresIn: ACCESS_TOKEN_TIME_TO_LIVE
        })
        return context
    } 

    private async generateRefreshToken(context: ITokenContext): Promise<ITokenContext>{
        context.refreshToken = randomBytes(32).toString('hex')
        return Promise.resolve(context)
    }

    private async generateCrsfToken(context: ITokenContext): Promise<ITokenContext>{
        context.crsfToken = randomBytes(32).toString('hex')
        return Promise.resolve(context)
    }

    private async saveSession(context: ITokenContext): Promise<ITokenContext> {
        const { user, deviceId, refreshToken, crsfToken }  = context
        if(!user || !deviceId || !refreshToken || !crsfToken) throw new Error("Thiếu thông tin trong context để khởi tạo phiên đăng nhập")
        
        const sessionId = randomBytes(16).toString('hex')
        const sessionData: ISessionData = {
            userId : user.id.toString(),
            deviceId,
            refreshToken,
            crsfToken,
            createdAt: Date.now(),
            lastUsed: Date.now(),
            wasUsed: false,
            isRevoked: false,
            expiresAt: Date.now() + REFRESH_TOKEN_TIME_TO_LIVE * 1000
        }

        const userSessions : string[] = (await this.cacheManager.get(`user:${user.id}:sessions`)) ?? []
        if(userSessions.length >= MAX_SESSION_PER_USER){
            await this.removeOldestSession(user.id, userSessions, context)
        }

        await Promise.all([
            this.cacheManager.set(`session:${sessionId}:${context.guard}`, sessionData, REFRESH_TOKEN_TIME_TO_LIVE),
            this.cacheManager.set(`refresh_token:${refreshToken}:${context.guard}`, sessionId, REFRESH_TOKEN_TIME_TO_LIVE),
            this.cacheManager.set(`user:${user.id}:sessions:${context.guard}`, [...userSessions, sessionId])

        ])

        context.sessionId = sessionId
        return context

    }

    private async removeOldestSession(userId: bigint, sessions: string[], context: ITokenContext): Promise<void> {
        let oldestSessionId: string | null = null
        let oldestTimestamp = Infinity

        for(const sessionId of sessions){
            const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}:${context.guard}`)
            if(session && session.createdAt < oldestTimestamp){
                oldestTimestamp = session.createdAt
                oldestSessionId = sessionId
            }
        }

        if(oldestSessionId){
            const oldestSession: ISessionData | null = await this.cacheManager.get(`session:${oldestSessionId}:${context.guard}`)
            if(oldestSession){
                oldestSession.isRevoked = true
                await this.cacheManager.set(`session:${oldestSessionId}:${context.guard}`, oldestSession)
                await this.cacheManager.set(`user:${userId}:sessions:${context.guard}`, sessions.filter(id => id !== oldestSessionId))
            }else{
                this.logger.warn(`Không tìm thấy dữ liệu phiên cho sessionID ${oldestSessionId}`)
            }
        }

    }

    private async authReponse(context: ITokenContext, response: Response): Promise<ILoginResponse> {

        const { accessToken, crsfToken } = context
        if(!accessToken || !crsfToken) throw new Error('Thiếu Thông tin AccessToken hoặc CrsfToken trong Context')

        const decoded = this.jwtService.decode<IJwtPayload>(accessToken)
        const expiresAt = decoded.exp - Math.floor(Date.now() / 1000)

        response.cookie(REFRESH_TOKEN_COOKIE_NAME, context.refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: REFRESH_TOKEN_TIME_TO_LIVE * 1000,
            path: '/v1/auth/refresh'
        })
 
        return Promise.resolve({
            accessToken,
            crsfToken,
            expiresAt: expiresAt,
            tokenType: 'Bearer',
           
        })
    }

    async validateUser(context: ITokenContext): Promise<ITokenContext> {
        const { email, password } = context.authRequest

        const user = await this.prismaService.user.findUnique({
            where: { email }
        })
        if(!user || !await bcrypt.compare(password, user.password)){
            throw new UnauthorizedException("Email hoặc mật khẩu không chính xác")
        }
        const {password: _, ...userWithoutPassword} = user
        context.user = userWithoutPassword

        return context
    }

    async refreshToken(request: Request, guard: string, response: Response): Promise<ILoginResponse>{
        try {
            const refreshTokenCookie: string | undefined = request.cookies[REFRESH_TOKEN_COOKIE_NAME] as string | undefined
            const crsfToken = request.headers['x-crsf-token'] as string
            
            const context: ITokenContext = {
                refreshToken: refreshTokenCookie,
                crsfToken: crsfToken,
                guard: guard,
                authRequest: {} as AuthRequest,
                user: null,
                deviceId: ''
            }
            
            return await Promise.resolve(context)
                .then((context) => this.checkSession(context))
                .then((context) => this.generateAccessToken(context))
                .then((context) => this.generateRefreshToken(context))
                .then((context) => this.generateCrsfToken(context))
                .then((context) => this.saveSession(context))
                .then((context) => this.authReponse(context, response))
        } catch (error) {
            return ExceptionHandler.error(error, this.logger) 
        }
        
        
    }   

    private async checkSession(context: ITokenContext){
      
        if(!context.crsfToken || !context.refreshToken){
            throw new UnauthorizedException("Thiếu Refresh Token hoặc CRSF Token")
        }
        const sessionId: string | null = await this.cacheManager.get(`refresh_token:${context.refreshToken}:${context.guard}`)
        if(!sessionId){
            throw new UnauthorizedException("Refresh token không hợp lệ, hoặc đã hết hạn")
        }
        const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}:${context.guard}`)
        if(!session){
            throw new UnauthorizedException("Không tìm thấy thông tin của phiên")
        }

        if(session.crsfToken !== context.crsfToken){
            throw new UnauthorizedException("Crsf Token không chính xác")
        }

        if(session.isRevoked && session.wasUsed){
            throw new UnauthorizedException("Phát hiện RefreshToken đang được sử dụng lại, Vô hiệu các phiên đăng nhập của user")
            /** Xử lý revoke toàn bộ refreshToken của user trên mọi thiết bị */
        }
        
        if(session.expiresAt < Date.now()){
            throw new UnauthorizedException("Refresh Token đã hết hạn")
        }

        const user: User = (await this.userService.show(session.userId))!

       
        session.wasUsed = true
        session.lastUsed = Date.now()

        await this.cacheManager.set(`session:${sessionId}:${context.guard}`, session)
        context.user = user
        context.deviceId = session.deviceId
        context.sessionId = sessionId

        return context
    }

}
