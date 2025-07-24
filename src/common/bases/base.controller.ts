/* eslint-disable @typescript-eslint/no-unused-vars */
import { Body, Controller, HttpStatus, Post, Req, HttpCode, Get, UseGuards, UnauthorizedException, Res, Param } from '@nestjs/common';
import { ValidationPipe } from 'src/pipes/validation.pipe';

import { ApiResponse, TApiReponse } from 'src/common/bases/api-reponse';
import { Request, Response } from 'express';
import { common } from 'src/config/constant';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { GuardType } from 'src/common/guards/jwt-auth.guard'; 
import { Logger } from "@nestjs/common";
import { BaseServiceInterface } from './base.service';
import { TResult } from './base.service';
import { convertResponse } from 'src/utils/helper';


const GUARD = common.admin

export class BaseController<
    T extends {id: bigint}, 
    S extends BaseServiceInterface<T>
> {
    private readonly logger = new Logger(BaseController.name)

    constructor(
       private readonly service: S
    ) {}

   

    


}
