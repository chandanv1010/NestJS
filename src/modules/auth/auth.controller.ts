/* eslint-disable @typescript-eslint/no-unused-vars */
import { Body, Controller, HttpStatus, Post, Req, HttpCode, Get, UseGuards, UnauthorizedException, Res, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ValidationPipe } from 'src/pipes/validation.pipe';
import { ForgotPasswordRequest } from './dto/forgot-password.request.dto';
import { AuthRequest } from './dto/auth.request.dto';
import { ResetPasswordRequest } from './dto/reset-password.request.dto';

import { ApiResponse, TApiReponse } from 'src/common/bases/api-reponse';
import { ILoginResponse } from './auth.interface';
import { Request, Response } from 'express';
import { UserService } from '../user/user/user.service';
import { common } from 'src/config/constant';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { GuardType } from 'src/common/guards/jwt-auth.guard'; 
import { IUserResponse } from '../user/user/user.interface';
import { UserDto } from '../user/user/dto/user.response.dto';
import { DataTransformer } from 'src/common/bases/data.transform';
import { User } from '@prisma/client';

const GUARD = common.admin

@Controller('v1/auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService,
        private readonly transformer: DataTransformer<User, UserDto>
    ) {}

    @Post('/login')
    @HttpCode(HttpStatus.OK)
    async login(
        @Body(new ValidationPipe()) authRequest: AuthRequest,
        @Req() request: Request,
        @Res({passthrough: true}) response : Response
    ): Promise<TApiReponse<ILoginResponse>> {
        const dataResponse = await this.authService.authenticate(authRequest, request, GUARD, response);
        return ApiResponse.ok(dataResponse, "Đăng nhập thành công", HttpStatus.OK)
    }


    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Get('/me')
    @HttpCode(HttpStatus.OK)
    async me(@Req() request: Request): Promise<TApiReponse<UserDto>> {

        try {
            const auth = (request.user as { userId: number | string })
            const user = await this.userService.show(auth.userId)
            if(!user){
                throw new UnauthorizedException("Thông tin không hợp lệ")
            }
            return ApiResponse.ok(this.transformer.transformSingle(user, UserDto), "Success!", HttpStatus.OK)          
        }catch (error) {
            console.log(error)
            throw error
        }   
    }

    @Post('/refresh')
    @HttpCode(HttpStatus.OK)
    async refresh(
        @Req() request: Request,
        @Res({passthrough: true}) response : Response
     ): Promise<TApiReponse<ILoginResponse>> {
        const res = await this.authService.refreshToken(request, GUARD, response)
        return ApiResponse.ok(res, "RefreshToken thành công", HttpStatus.OK)
    }

    @Post('/logout')
    @HttpCode(HttpStatus.OK)
    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    async logout(
        @Req() request: Request,
        @Res({passthrough: true}) response : Response
     ): Promise<TApiReponse<string>> {
        const res = await this.authService.logout(request, GUARD, response)
        return ApiResponse.message("Đăng xuất thành công", HttpStatus.OK)
    }

    @Post('/forgot-password')
    @HttpCode(HttpStatus.OK)
    async forgotPassword(
        @Body(new ValidationPipe()) forgotPasswordRequest: ForgotPasswordRequest,
        @Req() request: Request,
        @Res({passthrough: true}) response : Response
     ): Promise<TApiReponse<string>> {
        const res = await this.authService.forgotPassword(forgotPasswordRequest, request, response)
        return ApiResponse.message(res.message, HttpStatus.OK)
    }

    @Get('/verify-reset-token/:token')
    @HttpCode(HttpStatus.OK)
    async verifyResetToken(
        @Param('token') token: string,
     ): Promise<TApiReponse<string>> {
        const res = await this.authService.verifyResetToken(token)
        return ApiResponse.message(res.message, HttpStatus.OK)
    }

    @Post('/reset-password')
    @HttpCode(HttpStatus.OK)
    async resetPassword(
        @Body(new ValidationPipe()) resetPasswordRequest: ResetPasswordRequest
     ): Promise<TApiReponse<string>> {
        const res = await this.authService.resetPassword(resetPasswordRequest.token, resetPasswordRequest.password)
        return ApiResponse.message(res.message, HttpStatus.OK)
    }

}
