/* eslint-disable @typescript-eslint/no-unused-vars */
import { Injectable, InternalServerErrorException, UnauthorizedException, Inject, Logger, NotFoundException, BadRequestException, HttpException } from '@nestjs/common';


import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { Request } from 'express';
import { Response } from 'express';

import { ExceptionHandler } from 'src/utils/exception-handler.util';


import { UserCatalogue } from '@prisma/client';
import { BaseService } from 'src/common/bases/base.service';
import { PrismaService } from "../../prisma/prisma.service";
import { UserCatalogueRepository } from './user.catalogue.repository';
import { UserCatalogueDto } from './dto/user.catalogue.response.dto';


@Injectable()
export class UserCatalogueService extends BaseService<UserCatalogueRepository, UserCatalogue, UserCatalogueDto> {
    
    private readonly serviceLogger = new Logger(UserCatalogueService.name)


    constructor(
        private readonly userCatalogueRepository: UserCatalogueRepository,
        protected readonly prismaService: PrismaService
    ){
        super(userCatalogueRepository, prismaService, UserCatalogueDto)
    }

    
    
}
