/* eslint-disable @typescript-eslint/no-unused-vars */
import { Body, Controller, HttpStatus, Post, Req, HttpCode, Get, UseGuards, UnauthorizedException, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ValidationPipe } from 'src/pipes/validation.pipe';
import { AuthRequest } from './auth.request.dto';
import { ApiResponse, TApiReponse } from 'src/common/bases/api-reponse';
import { ILoginResponse } from './auth.interface';
import { Request, Response } from 'express';
import { UserService } from '../user/user.service';
import { common } from 'src/config/constant';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { GuardType } from 'src/common/guards/jwt-auth.guard'; 
import { IUserResponse } from '../user/user.interface';

const GUARD = common.admin

@Controller('v1/auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService
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
    async me(@Req() request: Request): Promise<TApiReponse<IUserResponse>> {

        try {
            const auth = (request.user as { userId: number | string })
            const user = await this.userService.show(auth.userId)
            if(!user){
                throw new UnauthorizedException("Thông tin không hợp lệ")
            }
            const {password, ...userFields } = user

            const userWithoutPassword = { 
                ...userFields,
                id: user.id.toString()
            }
            return ApiResponse.ok(userWithoutPassword as IUserResponse, "Success!", HttpStatus.OK)          
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

}
