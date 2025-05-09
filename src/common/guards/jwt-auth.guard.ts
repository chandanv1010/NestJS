import { Injectable, ExecutionContext, UnauthorizedException } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { Reflector } from "@nestjs/core";
import { Observable } from "rxjs";
import { common } from 'src/config/constant';
import { Request } from 'express';
import { SetMetadata } from "@nestjs/common";

const GUARD_KEY = common.admin

export interface IRequestWithGuardType extends Request {
    GuardType: string | string[] 
}

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {


    constructor(
        private readonly reflector: Reflector
    ){
        super()
    }

    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const requireGuard = this.reflector.getAllAndOverride<string | string[]>(GUARD_KEY, [
            context.getHandler(),
            context.getClass()
        ])
        
        const request = context.switchToHttp().getRequest<IRequestWithGuardType>()
        request.GuardType = requireGuard
        return super.canActivate(context)
    }

    handleRequest<TUser = unknown>(err: unknown, user: unknown, info: unknown, context: ExecutionContext, status?: unknown): TUser {
        if(err){
            if(err instanceof Error){
                throw err
            }else{
                throw new UnauthorizedException("Token không hợp lệ hoặc hết hạn sử dụng")
            }
        }
        if(!user){
            throw new UnauthorizedException("Token không hợp lệ, hoặc hết hạn sử dụng")
        }
        console.log(info, context, status);
        return user as TUser
    }
}

export const GuardType = (guard: string | string[]) => SetMetadata(GUARD_KEY, guard)
