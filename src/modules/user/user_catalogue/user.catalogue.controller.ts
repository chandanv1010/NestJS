/* eslint-disable @typescript-eslint/no-unused-vars */
import { Body, Controller, HttpStatus, Post, Req, HttpCode, Get, UseGuards, UnauthorizedException, Res, Param } from '@nestjs/common';
import { ValidationPipe } from 'src/pipes/validation.pipe';

import { ApiResponse, TApiReponse } from 'src/common/bases/api-reponse';
import { Request, Response } from 'express';
import { common } from 'src/config/constant';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { GuardType } from 'src/common/guards/jwt-auth.guard'; 
import { StoreRequest } from './dto/store.request';
import { UpdateRequest } from './dto/update.request';
import { UserCatalogueService } from './user.catalogue.service';
import { Logger } from "@nestjs/common";
import { BaseController } from 'src/common/bases/base.controller';
import { UserCatalogue } from '@prisma/client';
import { IUserCatalogueResponse } from './user.catalogue.interface';
import { UserCatalogueDto } from './dto/user.catalogue.response.dto';

const GUARD = common.admin

@Controller('v1/user_catalogues')
export class UserCatalogueController extends BaseController<
    UserCatalogue, 
    UserCatalogueService, 
    StoreRequest,
    UpdateRequest, 
    UserCatalogueDto
> {
    private readonly controllerLogger = new Logger(BaseController.name)


    constructor(
       private readonly userCatalogueService: UserCatalogueService
    ) {
        super(userCatalogueService);
    }


}
