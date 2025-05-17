/* eslint-disable @typescript-eslint/no-unused-vars */
import { Injectable, InternalServerErrorException, UnauthorizedException, Inject, Logger, NotFoundException, BadRequestException, HttpException } from '@nestjs/common';
import { AuthRequest } from './dto/auth.request.dto';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { UserWithoutPassword } from '../user/user/user.interface';
import { ILoginResponse, IJwtPayload, ITokenContext, ISessionData, IForgotPasswordContext } from './auth.interface';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { Request } from 'express';
import { ExceptionHandler } from 'src/utils/exception-handler.util';
import { Response } from 'express';
import { UserService } from '../user/user/user.service';
import { User } from '@prisma/client';
import { ForgotPasswordRequest } from './dto/forgot-password.request.dto';
import { MailService } from '../mail/mail.service';
import * as crypto from 'crypto'
import { QueueService } from '../queue/queue.service';

const ACCESS_TOKEN_TIME_TO_LIVE = '1h'
const REFRESH_TOKEN_TIME_TO_LIVE = 30 * 24 * 60 * 60 * 1000
const MAX_SESSION_PER_USER = 5;
const REFRESH_TOKEN_COOKIE_NAME = 'nestJs_refresh_token';

const PASSWORD_RESET_MAX_ATTEMPS = 3 //Số lần tối đa trong 1 khung thời gian
const PASSWORD_RESET_WINDOW = 60 * 60 * 1000 // 1 giờ tính bằng giây
const PASSWORD_RESET_LOCKOUT = 24 * 60 * 60 * 1000 // thời gian khóa 24 giờ


@Injectable()
export class AuthService {
    
    private readonly logger = new Logger(AuthService.name)


    constructor(
        private readonly prismaService: PrismaService,
        private readonly jwtService: JwtService,
        private readonly userService: UserService,
        private readonly mailService: MailService,
        private readonly queueService: QueueService,
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
        console.log(user, deviceId, refreshToken, crsfToken);
        
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
                .then((context) => this.validateTokens(context))
                .then((context) => this.findSessionId(context))
                .then((context) => this.getSessionData(context))
                .then((context) => this.validateCrsfToken(context))
                .then((context) => this.checkSessionRevocation(context))
                .then((context) => this.checkSessionExpiration(context))
                .then((context) => this.getUser(context))
                .then((context) => this.markSessionAsUsed(context))
                .then((context) => this.generateAccessToken(context))
                .then((context) => this.generateRefreshToken(context))
                .then((context) => this.generateCrsfToken(context))
                .then((context) => this.saveSession(context))
                .then((context) => this.authReponse(context, response))
        } catch (error) {
            return ExceptionHandler.error(error, this.logger) 
        }
    } 
    
    private async validateTokens(context: ITokenContext): Promise<ITokenContext>{
        if(!context.crsfToken || !context.refreshToken){
            throw new UnauthorizedException("Thiếu Refresh Token hoặc CRSF Token")
        }
        return Promise.resolve(context)
    }

    private async findSessionId(context: ITokenContext): Promise<ITokenContext>{    
        const sessionId: string | null = await this.cacheManager.get(`refresh_token:${context.refreshToken}:${context.guard}`)
        if(!sessionId){
            throw new UnauthorizedException("Refresh token không hợp lệ, hoặc đã hết hạn")
        }
        context.sessionId = sessionId
        return context;
    }

    private async getSessionData(context: ITokenContext): Promise<ITokenContext>{
        const { sessionId, guard } = context
        const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}:${guard}`)
        if(!session){
            throw new UnauthorizedException("Không tìm thấy thông tin của phiên")
        }
        context.session = session
        context.deviceId = session.deviceId
        return context
    }

    private validateCrsfToken(context: ITokenContext): Promise<ITokenContext>{
        const { session, crsfToken } = context

        if(!session || !crsfToken){
            throw new UnauthorizedException("Thiếu thông tin session hoặc CrsfToken trong context")
        }

        if(session.crsfToken !== crsfToken){
            throw new UnauthorizedException("Crsf Token không chính xác")
        }

        return Promise.resolve(context)
    }

    private async checkSessionRevocation(context: ITokenContext): Promise<ITokenContext>{
        if(!context.session){
            throw new UnauthorizedException("Không tìm thấy thông tin session")
        }
        const { isRevoked, wasUsed }  = context.session
        if(isRevoked || wasUsed){
            /** Có thể đang bị tái sử dụng RefreshToken - Nghĩ đến 1 trường hợp là đang có dấu hiệu của việc bị tấn công */
            this.logger.warn(`Phát hiện tái sử dụng RefreshToken cho sessionId: ${context.sessionId}, UserId: ${context.session?.userId}`)

            await this.revokeAllUserSessions(context.session.userId, context.guard)
            throw new UnauthorizedException("Phát hiện RefreshToken đang được sử dụng lại, Vô hiệu các phiên đăng nhập của user")
        }

        return context
    }

    private async revokeAllUserSessions(userId: string, guard: string): Promise<void>{
        try {
            const userSessions: string[] = await this.cacheManager.get(`user:${userId}:sessions:${guard}`) || []
            
            this.logger.warn(`Bắt đầu vô hiệu hóa tất cả ${userSessions.length} của người dùng ${userId}`)
            for(const sessionId of userSessions){
                const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}:${guard}`)
                if(session){
                    session.isRevoked = true
                    await this.cacheManager.set(`session:${sessionId}:${guard}`, session)
                    await this.cacheManager.del(`refresh_token:${session.refreshToken}:${guard}`)
                    this.logger.warn(`Đã vô hiệu hóa phiên ${sessionId} của người dùng ${userId} trên thiết bị ${session.deviceId}`)
                }
            }

            await this.cacheManager.set(`user:${userId}:sessions:${guard}`, [])
            this.logger.warn(`Đã vô hiệu hóa thành công toàn bộ ${userSessions.length} của người dùng ${userId} do phát hiện refreshToken đang được sử dụng lại`)


        } catch (error) {
            this.logger.error(`Có vấn đề xảy ra trong quá trình vô hiệu hóa phiên của người dùng userID ${userId}: ${error instanceof Error ? error.message : 'Không xác định'} stack: ${error instanceof Error ? error.stack : undefined}`)
            throw new InternalServerErrorException("Lỗi khi vô hiệu hóa")
        }
    }

    private async checkSessionExpiration(context: ITokenContext): Promise<ITokenContext>{
        if(!context.session){
            throw new UnauthorizedException("Thiếu thông tin session trong Context")
        }

        if(context.session.expiresAt < Date.now()){
            throw new UnauthorizedException("RefrehToken đã hết hạn")
        }

        return Promise.resolve(context)
    }

    private async getUser(context: ITokenContext): Promise<ITokenContext>{
        if(!context.session){
            throw new UnauthorizedException("Thiếu thông tin session trong Context")
        }
        const user: User = (await this.userService.findById(context.session.userId))!
        context.user = user
        return context
    }

    private async markSessionAsUsed(context: ITokenContext): Promise<ITokenContext>{
        if(!context.session){
            throw new UnauthorizedException("Thiếu thông tin session trong Context")
        }
        context.session.wasUsed = true
        context.session.lastUsed = Date.now()
        await this.cacheManager.set(`session:${context.sessionId}:${context.guard}`, context.session)
        return context
    }


    async logout(request: Request, guard: string, response: Response): Promise<void>{
        try {
            
            const context: ITokenContext  = {
                guard: guard, 
                deviceId: this.generateDeviceId(request),
                authRequest: {} as AuthRequest,
                user: null,
                request: request
            }

            const auth = (request.user as { userId: number | string })
            if(!auth){
                throw new UnauthorizedException("Không xác định được người dùng")
            }
            context.user = (await this.userService.findById(auth.userId))!
            await Promise.resolve(context)
               .then((context) => this.findUserSessions(context))
               .then((context) => this.findDeviceSession(context))
               .then((context) => this.revokeSession(context))
               .then((context) => this.removeSessionFromUser(context))
               .then((context) => this.clearRefreshTokenCookie(context, response))
               .then((context) => this.addTokenToBlacklist(context))


        } catch (error) {
            this.logger.error(`Có vấn đề xảy ra trong quá trình đăng xuất của người dùng : ${error instanceof Error ? error.message : 'Không xác định'} stack: ${error instanceof Error ? error.stack : undefined}`)
            response.cookie(REFRESH_TOKEN_COOKIE_NAME, '', {
                httpOnly: true,
                secure: false,
                sameSite: "lax",
                maxAge: 0,
                path: '/v1/auth/refresh'
            })
            throw new InternalServerErrorException("Lỗi khi đăng xuất")
        }
    }

    private async findUserSessions(context: ITokenContext): Promise<ITokenContext>{
        if(!context.user){
            throw new UnauthorizedException("Không xác định được user hợp lệ")
        }
        const session : string[] = await this.cacheManager.get(`user:${context.user.id}:sessions:${context.guard}`) || []
        context.userSessions = session
        return context
    }

    private async findDeviceSession(context: ITokenContext): Promise<ITokenContext>{
        if(!context.userSessions || !context.deviceId){
            throw new UnauthorizedException("Thiếu thông tin sessions của user hoặc thông tin thiết bị")
        }
        for(const sessionId of context.userSessions){
            const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}:${context.guard}`)
            if(session && session.deviceId === context.deviceId){
                context.sessionId = sessionId
                context.session = session
                break;
            }
        }

        if(!context.sessionId || !context.session){
            this.logger.warn(`Không tìm thấy phiên đăng nhập trên thiết bị ${context.deviceId} của người dùng ${context.user?.id}`)
        }

        return context
    }

    private async revokeSession(context: ITokenContext): Promise<ITokenContext> {
        if(!context.user){
            throw new UnauthorizedException("Không xác định được user hợp lệ")
        }
        if(!context.session || !context.sessionId){
            return context
        }

        context.session.isRevoked = true
        await this.cacheManager.set(`session:${context.sessionId}:${context.guard}`, context.session)
        await this.cacheManager.del(`refresh_token:${context.session.refreshToken}:${context.guard}`)
        this.logger.warn(`Đã vô hiệu hóa phiên ${context.sessionId} của người dùng ${context.user.id} trên thiết bị ${context.deviceId}`)
        return context
    }

    private async removeSessionFromUser(context: ITokenContext): Promise<ITokenContext>{
        if(!context.user){
            throw new UnauthorizedException("Không xác định được user hợp lệ")
        }

        if(!context.sessionId){
            return context
        }

        const updateSessions = context.userSessions?.filter(id => id !== context.sessionId)
        await this.cacheManager.set(`user:${context.user.id}:sessions:${context.guard}`, updateSessions)
        this.logger.log(`Đã cập nhật danh sách phiên của người dùng ${context.user.id}`)

        return context
    }

    private async clearRefreshTokenCookie(context: ITokenContext, response: Response): Promise<ITokenContext>{
        response.cookie(REFRESH_TOKEN_COOKIE_NAME, '', {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 0,
            path: '/v1/auth/refresh'
        })

        return Promise.resolve(context)
    }

    private async addTokenToBlacklist(context: ITokenContext): Promise<ITokenContext>{
        const authHeader = context.request?.headers?.authorization
        if(!authHeader){
            return Promise.resolve(context)
        }

        const token = authHeader.substring(7)
        try {
            const payload = this.jwtService.verify<IJwtPayload>(token)
            const now = Math.floor(Date.now() / 1000)
            const ttl = payload.exp - now
            if(ttl > 0){
                await this.cacheManager.set(`blacklist:token:${token}`, true, ttl)
                this.logger.log(`Đã thêm access token vào blacklist, hết hạn sau : ${ttl} giây`)
            }

        } catch (error) {
            this.logger.error(`Lỗi khi thêm accessToken vào blacklist`)
        }


        return context;
    }

    async forgotPassword(forgotPasswordRequest: ForgotPasswordRequest, request: Request, response: Response): Promise<{message: string}>{
    // async forgotPassword(forgotPasswordRequest: ForgotPasswordRequest, request: Request, response: Response): Promise<IForgotPasswordContext>{
        try {
            const context = {
                email: forgotPasswordRequest.email
            }
            
            return await Promise.resolve(context)
                .then(context => this.checkPasswordResetRateLimit(context))
                .then(context => this.checkEmailExists(context))
                .then(context => this.generateResetToken(context))
                .then(context => this.saveResetToken(context))
                .then(context => this.sendResetMail(context))
                .then(context => this.getResponse(context))
        } catch (error) {
            return ExceptionHandler.error(error, this.logger) 
        }
    }

    private async checkPasswordResetRateLimit(context: IForgotPasswordContext): Promise<IForgotPasswordContext>{
        const emailCacheKey = `password_reset:email:${context.email}`

        const emailLocked = await this.cacheManager.get<boolean>(`${emailCacheKey}:locked`)
        if(emailLocked){
            this.logger.warn(`Yêu cầu đặt lại mật khẩu bị từ chối: Email ${context.email} bị khóa`)
            throw new InternalServerErrorException('Quá nhiều yêu cầu đặt lại mật khẩu. Hãy thử lại sau 24 tiếng')
        }

        const emailAttempts = await this.cacheManager.get<number>(emailCacheKey) || 0
        const newEmailAttempts = emailAttempts + 1

        await this.cacheManager.set(emailCacheKey, newEmailAttempts, 100000)

        console.log(newEmailAttempts, PASSWORD_RESET_MAX_ATTEMPS);
        

        if(newEmailAttempts > PASSWORD_RESET_MAX_ATTEMPS) {
            this.logger.warn(`Email ${context.email} đã vượt quá giới hạn yêu cầu đặt lại mật khẩu. Đã khóa chức năng trong 24 tiếng`)
            await this.cacheManager.set(`${emailCacheKey}:locked`, true, PASSWORD_RESET_LOCKOUT)
            throw new InternalServerErrorException('Quá nhiều yêu cầu đặt lại mật khẩu, Hãy thử lại sau 24 giờ')
        }
        return context
    }


    private async checkEmailExists(context: IForgotPasswordContext): Promise<IForgotPasswordContext>{
        const user = await this.userService.findByEmail(context.email)
        if(!user){
            throw new NotFoundException("Yêu cầu lấy lại mật khẩu không hợp lệ")
        }
        context.user = user
        return context
    }

    private async generateResetToken(context: IForgotPasswordContext): Promise<IForgotPasswordContext>{
        if(!context.user) return context

        const resetToken = randomBytes(32).toString('hex')
        const hasedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000 )
        
        context.resetToken = resetToken
        context.hashedToken = hasedToken
        context.expiresAt = expiresAt

        return Promise.resolve(context)
    }

    private async saveResetToken(context: IForgotPasswordContext): Promise<IForgotPasswordContext> {
        try {
             if(!context.user || !context.hashedToken || !context.resetToken) return context
            await this.userService.save({
                passwordResetToken: context.hashedToken,
                passwordResetTokenExpires: context.expiresAt
            }, Number(context.user.id))
            this.logger.log(`Đã tạo và lưu resetToken vào database cho người dùng ${context.user.id}`)

            return context
            
        } catch (error) {
            this.logger.error(`Lỗi khi lưu token đặt lại mật khẩu: ${error instanceof Error ? error.message : 'Không xác định'}`)
            throw new InternalServerErrorException('Không thể xử lý yêu cầu đặt lại mật khẩu')
        }
       
    }

    private async sendResetMail(context: IForgotPasswordContext): Promise<IForgotPasswordContext> {
        try {
            if(!context.resetToken){
                throw new BadRequestException('Tạo mã reset mật khẩu không thành công')
            }

            await this.queueService.addJob<{email: string, token: string}>('send-reset-email', {
                email: context.email,
                token: context.resetToken,
            }, undefined)
            // await this.mailService.sendForgotResetEmail(context.email, context.resetToken)
            this.logger.log(`Đã thêm Email vào hàng đợi từ : AuthService`);
            return context
        } catch (error) {
            this.logger.error(`Lỗi khi lưu token đặt lại mật khẩu: ${error instanceof Error ? error.message : 'Không xác định'}`)
            return context
        }
    }

    private async getResponse(context: IForgotPasswordContext): Promise<{message: string}> {
        if(context.hashedToken) delete context.hashedToken
        if(context.resetToken) delete context.resetToken

        return Promise.resolve({message: `Bạn sẽ nhận được Email hướng dẫn đặt lại mật khẩu tại địa chỉ  ${context.email}. Hãy làm theo hướng dẫn`})
    }

    async verifyResetToken(token: string):  Promise<{message: string}> {
        
        const hasedToken = crypto.createHash('sha256').update(token).digest('hex')
        const user = await this.userService.findResetToken(hasedToken)
        if(!user){
            throw new BadRequestException('Token không hợp lệ hoặc đã hết hạn')
        }

        return Promise.resolve({message: 'Verify Reset Token thành công'})
    }

    async resetPassword(token: string, password: string): Promise<{message: string}> {
        const hasedToken = crypto.createHash('sha256').update(token).digest('hex')
        const user = await this.userService.findResetToken(hasedToken)
        if(!user){
            throw new BadRequestException('Token không hợp lệ hoặc đã hết hạn')
        }
        const payload = {
            password: await bcrypt.hash(password, 10),
            passwordResetToken: null,
            passwordResetTokenExpires: null
        }

        await this.userService.save(payload, Number(user.id))

        return Promise.resolve({ message: 'Thay đổi mật khẩu thành công, hãy thử đăng nhập lại' })
    }
    
}
